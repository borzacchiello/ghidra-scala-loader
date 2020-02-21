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

import java.io.{File, PrintWriter}

import generic.jar.ResourceFile

import scala.jdk.CollectionConverters._

class ScalaScriptProvider extends GhidraScriptProvider {
	override def getDescription: String = "Scala"

	override def getExtension: String = ".scala"

	override def deleteScript(scriptSource: ResourceFile): Boolean = ???

	override def getScriptInstance(resourceFile: ResourceFile, printWriter: PrintWriter): GhidraScript = ???

	private def forceClassReload(): Unit = new JavaScriptClassLoader

	protected def getClassFile(sourceFile: ResourceFile, className: String): File = ???

	protected def needsCompile(sourceFile: ResourceFile, classFile: File): Boolean = ???

	protected def scriptCompiledExternally(classFile: File): Boolean = ???

	protected def areAllParentClassesUpToDate(sourceFile: ResourceFile): Boolean = ???

	protected def compile(sourceFile: ResourceFile, writer: PrintWriter): Boolean = ???

	private def doCompile(sourceFile: ResourceFile, writer: PrintWriter): Boolean = ???

	private def getParentClasses(scriptSourceFile: ResourceFile): List[Class[_]] = ???

	private def getScriptClass(scriptSourceFile: ResourceFile): Class[_] = ???

	private def compileParentClasses(sourceFile: ResourceFile, writer: PrintWriter): Unit = ???

	private def getSourceFile(c: Class[_]): ResourceFile = ???

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

	override def createNewScript(resourceFile: ResourceFile, s: String): Unit = ???

	override def getCommentCharacter: String = "//"
}
