/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.app.script

import java.io.{File, FileWriter, PrintWriter}

import generic.io.NullPrintWriter
import generic.jar.ResourceFile
import ghidra.app.util.headless.HeadlessScript
import ghidra.util.Msg
import javax.tools.JavaFileObject.Kind

import scala.jdk.CollectionConverters._
import scala.tools.nsc.MainClass

class ScalaScriptProvider extends GhidraScriptProvider {
	private var loader = new JavaScriptClassLoader

	override def getDescription: String = "Scala"

	override def getExtension: String = ".scala"

	override def deleteScript(scriptSource: ResourceFile): Boolean = {
		getClassFile(scriptSource, GhidraScriptUtil.getBaseName(scriptSource)).delete()
		super.deleteScript(scriptSource)
	}

	override def getScriptInstance(sourceFile: ResourceFile, printWriter: PrintWriter): GhidraScript = {
		val writer = Option(printWriter) match {
			case None => new NullPrintWriter
			case Some(w) => w
		}
		val clazzFile = getClassFile(sourceFile, GhidraScriptUtil.getBaseName(sourceFile))
		if (!clazzFile.exists
			|| sourceFile.lastModified() > clazzFile.lastModified()
			|| !parentClassesUpToDate(sourceFile)) {
			val info = GhidraScriptUtil.getScriptInfo(sourceFile)
			info.setCompileErrors(true)
			if (!compile(sourceFile, writer)) {
				writer.flush()
				throw new ClassNotFoundException(s"Unable to compile class: ${sourceFile.getName}")
			}
			compileParentClasses(sourceFile, writer)
			forceClassReload()
			info.setCompileErrors(false)
			writer.println(s"Successfully compiled: ${sourceFile.getName}")
		} else {
			forceClassReload()
		}
		val clazzName = GhidraScriptUtil.getBaseName(sourceFile)
		try {
			Class.forName(clazzName, true, loader).getConstructor().newInstance() match {
 				case source: GhidraScript =>
					source.setSourceFile(sourceFile)
					source
				case _ =>
					val message = s"Not a valid Ghidra script: ${sourceFile.getName}"
					writer.println(message)
					Msg.error(this, message)
					null
			}
		} catch {
			case e: GhidraScriptUnsupportedClassVersionError =>
				e.getClassFile.delete()
				getScriptInstance(sourceFile, writer)
		}
	}

	override def createNewScript(newScript: ResourceFile, category: String): Unit = {
		val scriptName = newScript.getName
		val dotpos = scriptName.lastIndexOf('.')
		val classname: String =
			if (dotpos >= 0)
				scriptName.substring(0, dotpos)
			else
				scriptName
		val writer = new PrintWriter(new FileWriter(newScript.getFile(false)))
		writeHeader(writer, category)
		writer.println("import ghidra.app.script.GhidraScript")
		Package.getPackages
			.filter(_.getName.startsWith("ghidra.program.model."))
			.foreach(pkg => writer.println(s"import ${pkg.getName}._"))
		val start =	s"""
                   |class $classname extends GhidraScript {
                   |    override def run() = {
                   |        """.stripMargin
		val end =    """    }
    		           |}""".stripMargin
		writer.print(start)
		writeBody(writer)
		writer.println(end)
		writer.close()
	}

	override def getCommentCharacter: String = "//"

	private def forceClassReload(): Unit = loader = new JavaScriptClassLoader

	protected def getClassFile(sourceFile: ResourceFile, className: String): File =
		GhidraScriptUtil.getClassFileByResourceFile(sourceFile, className).getFile(false)

	protected def scriptCompiledExternally(classFile: File): Boolean =
		Option(loader.lastModified(classFile)) match {
			case None => false
			case Some(modifiedTime) => classFile.lastModified() > modifiedTime
		}

	protected def parentClassesUpToDate(sourceFile: ResourceFile): Boolean = getParentClasses(sourceFile) match {
		case None => false
		case Some(parents) if parents.isEmpty => true
		case Some(parents) =>
			// Check each parent for modification
			parents.foldLeft(true)((upToDate, c) => getSourceFile(c) match {
				case None => upToDate
				case Some(parentSource) =>
					val parentClass = getClassFile(parentSource, c.getName)
					if (parentSource.lastModified() > parentClass.lastModified())
						false
					else
						upToDate
			})
	}

	private def compile(sourceFile: ResourceFile, writer: PrintWriter): Boolean = {
		new ResourceFileJavaFileObject(sourceFile.getParentFile, sourceFile, Kind.SOURCE)
		val outDir = GhidraScriptUtil.getScriptCompileOutputDirectory(sourceFile).getAbsolutePath
		Msg.trace(this, s"Compiling script $sourceFile to dir $outDir")
		val args = Array(
			"-g:source",
			"-d", outDir,
			"-sourcepath", sourcePath,
			"-classpath", classPath,
			sourceFile.getAbsolutePath
		)
		(new MainClass).process(args)
	}

	private def compileParentClasses(sourceFile: ResourceFile, writer: PrintWriter): Unit = {
		(getParentClasses(sourceFile), getScriptClass(sourceFile)) match {
			case (None, _) | (_, None) => ()
			case (Some(parents), _) if parents.isEmpty => ()
			case (Some(parents), Some(script)) =>
				def compileOne(c: Class[_]): Unit = getSourceFile(c) match {
					case None => ()
					case Some(f) if compile(f, writer) => ()
					case _ => Msg.error(this, s"Failed to recompile class $c")
				}
				// Recompile in reverse order
				(script :: parents).reverse.foreach(compileOne)
		}
	}

	private def getParentClasses(source: ResourceFile): Option[List[Class[_]]] = getScriptClass(source) match {
		case None => None
		case Some(scriptClass) =>
			def getSuperClasses(c: Class[_]): List[Class[_]] =
				if (c == null) Nil else c :: getSuperClasses(c.getSuperclass)
			val filter = (c: Class[_]) =>
				!(c.equals(classOf[GhidraScript]) || c.equals(classOf[HeadlessScript]))
			Some(getSuperClasses(scriptClass).filter(filter))
	}

	private def getScriptClass(scriptSourceFile: ResourceFile): Option[Class[_]] = {
		val clazzName = GhidraScriptUtil.getBaseName(scriptSourceFile)
		try {
			Some(Class.forName(clazzName, true, new JavaScriptClassLoader))
		} catch {
			case e @ (_: NoClassDefFoundError | _: ClassNotFoundException) =>
				val message =  s"Unable to find class file for script file: $scriptSourceFile"
				Msg.error(this, message, e)
				None
			case e: GhidraScriptUnsupportedClassVersionError => e.getClassFile.delete; None
		}
	}

	private def getSourceFile(c: Class[_]): Option[ResourceFile] = {
		val filename = c.getName.replace('.', '/') + ".scala"
		val scriptDirs = GhidraScriptUtil.getScriptSourceDirectories.asScala
		scriptDirs.foldLeft(None: Option[ResourceFile])((found, dir) => found match {
			case Some(_) => found
			case None =>
				val f = new ResourceFile(dir, filename)
				if (f.exists)	Some(f) else None
		})
	}

	private def buildPath(dirs: Iterable[ResourceFile]): String = {
		val classpath = System.getProperty("java.class.path")
		val separator = System.getProperty("path.separator")
		dirs.foldLeft(classpath)((path, dir) =>	s"$path$separator${dir.getAbsolutePath}")
	}

	private def sourcePath: String =
		buildPath(GhidraScriptUtil.getScriptSourceDirectories.asScala)

	private def classPath: String =
		buildPath(GhidraScriptUtil.getScriptBinDirectories.asScala)
}
