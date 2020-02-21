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

import generic.io.NullPrintWriter
import generic.jar.ResourceFile
import ghidra.app.util.headless.HeadlessScript
import ghidra.util.Msg

import scala.tools.nsc.MainClass
import javax.tools.JavaFileObject.Kind
import java.io.File
import java.io.FileWriter
import java.io.PrintWriter
import java.util.ArrayList
import java.util.Collections
import java.util.List

import scala.reflect.internal.util.ScriptSourceFile

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

	private def getSourcePath(): String = ???

	private def getClassPath(): String = ???

	override def createNewScript(resourceFile: ResourceFile, s: String): Unit = ???

	override def getCommentCharacter: String = "//"
}
