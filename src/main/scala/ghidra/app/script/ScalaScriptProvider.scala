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
import ghidra.util.Msg

import scala.jdk.CollectionConverters._

class ScalaScriptProvider extends GhidraScriptProvider {
	val loader = new JavaScriptClassLoader

	override def getDescription: String = "Scala"

	override def getExtension: String = ".scala"

	override def deleteScript(scriptSource: ResourceFile): Boolean = {
		getClassFile(scriptSource, GhidraScriptUtil.getBaseName(scriptSource)).delete()
		super.deleteScript(scriptSource)
	}

	override def getScriptInstance(sourceFile: ResourceFile, printWriter: PrintWriter): Option[GhidraScript] = {
		val writer = Option(printWriter) match {
			case None => new NullPrintWriter
			case Some(w) => w
		}
		val clazzFile = getClassFile(sourceFile, GhidraScriptUtil.getBaseName(sourceFile))
		if (needsCompile(sourceFile, clazzFile))
			compile(sourceFile, writer)
		else
			forceClassReload()
		val clazzName = GhidraScriptUtil.getBaseName(sourceFile)
		try {
			Class.forName(clazzName, true, loader).newInstance() match {
 				case source: GhidraScript =>
					source.setSourceFile(sourceFile)
					Some(source)
				case _ =>
					val message = s"Not a valid Ghidra script: ${sourceFile.getName}"
					writer.println(message)
					Msg.error(this, message)
					None
			}
		} catch {
			case e: GhidraScriptUnsupportedClassVersionError =>
				e.getClassFile.delete()
				getScriptInstance(sourceFile, writer)
		}
	}


	private def forceClassReload(): Unit = new JavaScriptClassLoader

	protected def getClassFile(sourceFile: ResourceFile, className: String): File =
		GhidraScriptUtil.getClassFileByResourceFile(sourceFile, className).getFile(false)

	protected def needsCompile(sourceFile: ResourceFile, classFile: File): Boolean = {
		if (!classFile.exists() || sourceFile.lastModified() > classFile.lastModified())
			true
		else
			!areAllParentClassesUpToDate(sourceFile)
	}

	protected def scriptCompiledExternally(classFile: File): Boolean =
		Option(loader.lastModified(classFile)) match {
			case None => false
			case Some(modifiedTime) => classFile.lastModified() > modifiedTime
		}

	protected def areAllParentClassesUpToDate(sourceFile: ResourceFile): Boolean = ???

	protected def compile(sourceFile: ResourceFile, writer: PrintWriter): Boolean = ???

	private def doCompile(sourceFile: ResourceFile, writer: PrintWriter): Unit = ???

	private def getParentClasses(scriptSourceFile: ResourceFile): Option[List[Class[_]]] = ???

	private def getScriptClass(scriptSourceFile: ResourceFile): Option[Class[_]] = ???

	private def compileParentClasses(sourceFile: ResourceFile, writer: PrintWriter): Unit = {
		(getParentClasses(sourceFile), getScriptClass(sourceFile)) match {
			case (None, _) | (_, None) => ()
			case (Some(parents), _) if parents.isEmpty => ()
			case (Some(parents), Some(scriptClass)) =>
				(scriptClass :: parents).reverse
		}
	}

	private def getSourceFile(c: Class[_]): Option[ResourceFile] = {
		val filename = c.getName.replace('.', '/') + ".scala"
		val scriptDirs = GhidraScriptUtil.getScriptSourceDirectories.asScala
		scriptDirs.foldLeft(None[ResourceFile])((found, dir) => found match {
			case Some(_) => found
			case None =>
				val f = new ResourceFile(dir, filename)
				if (f.exists)	Some(f) else None
		})
	}

	private def getPath(dirs: Iterable[ResourceFile]): String = {
		val classpath = System.getProperty("java.class.path")
		val separator = System.getProperty("path.separator")
		dirs.foldLeft(classpath)((path, dir) =>
			s"${path}${separator}${dir.getAbsolutePath}")
	}

	private def getSourcePath: String =
		getPath(GhidraScriptUtil.getScriptSourceDirectories.asScala)

	private def getClassPath: String =
		getPath(GhidraScriptUtil.getScriptBinDirectories.asScala)

	override def createNewScript(newScript: ResourceFile, category: String): Unit = {
		val scriptName = newScript.getName()
		val dotpos = scriptName.lastIndexOf('.')
		val classname =
			if (dotpos >= 0)
				scriptName.substring(0, dotpos)
			else
				scriptName
		val writer = new PrintWriter(new FileWriter(newScript.getFile(false)))
		writeHeader(writer, category)
		writer.println("import ghidra.app.script.GhidraScript")
		Package.getPackages
			.filter(!_.getName.startsWith("ghidra.program.model."))
			.foreach(pkg => writer.println(s"import ${pkg.getName}.*;"))
		writer.println("")
		writer.println(s"public class ${classname} extends GhidraScript {")
		writer.println("")
		writer.println("    public void run() throws Exception {")
		writeBody(writer)
		writer.println("    }")
		writer.println("")
		writer.println("}")
		writer.close()
	}

	override def getCommentCharacter: String = "//"
}
