import io.shiftleft.semanticcpg.language._
import io.joern.dataflowengineoss.language._

def jesc(s: String): String =
  Option(s).getOrElse("").replace("\\", "\\\\").replace("\"", "\\\"").replace("\r", "").replace("\n", "\\n")

def nodeJson(n: Any): String = {
  try {
    val typ = try n.asInstanceOf[io.shiftleft.codepropertygraph.generated.nodes.StoredNode].label catch { case _: Throwable => "" }
    val code = n match {
      case a: io.shiftleft.codepropertygraph.generated.nodes.AstNode => Option(a.code).getOrElse("")
      case _ => ""
    }
    val line = n match {
      case a: io.shiftleft.codepropertygraph.generated.nodes.AstNode => a.lineNumber.map(_.toString).getOrElse("")
      case _ => ""
    }
    val file = n match {
      case a: io.shiftleft.codepropertygraph.generated.nodes.AstNode =>
        try a.file.name.l.headOption.getOrElse("") catch { case _: Throwable => "" }
      case _ => ""
    }
    s"""{"type":"${jesc(typ)}","code":"${jesc(code)}","line":"${jesc(line)}","file":"${jesc(file)}"}"""
  } catch {
    case _: Throwable =>
      s"""{"type":"unknown","code":"${jesc(n.toString)}","line":"","file":""}"""
  }
}

def nodeCode(n: Any): String =
  n match {
    case a: io.shiftleft.codepropertygraph.generated.nodes.AstNode => Option(a.code).getOrElse("")
    case _ => ""
  }

@main def main(cpgFile: String): Unit = {
  val cwe = sys.env.getOrElse("JOERN_CWE", "CWE-78")
  val maxFlows = sys.env.get("JOERN_MAXFLOWS").flatMap(s => scala.util.Try(s.toInt).toOption).getOrElse(40)
  val debug = sys.env.getOrElse("JOERN_DEBUG", "0") == "1"
  val maybe = importCpg(cpgFile, "p", true)
  if (maybe.isEmpty) {
    System.err.println(s"[c_flow_extract] importCpg failed: $cpgFile")
    return
  }
  val cpg0 = maybe.get

  val srcCalls = cpg0.call.name("copy_from_user|get_user|recv|read|fgets|scanf|getenv")
  val srcIds = cpg0.identifier.name("user|input|buf|buffer|arg|argv|path|name|data|cmd")
  val sources = (srcCalls ++ srcCalls.argument ++ srcIds).l

  val sinks = cwe match {
    case "CWE-78" =>
      cpg0.call.name("system|exec|popen|execl|execv|execvp").argument(1).l
    case "CWE-22" =>
      cpg0.call.name("open|fopen|access|stat|lstat|chdir|remove|unlink|rename").argument(1).l
    case "CWE-119" =>
      cpg0.call.name("strcpy|strcat|sprintf|vsprintf|memcpy|memmove|gets").argument(1).l
    case "CWE-190" =>
      cpg0.call.name("malloc|calloc|realloc|kmalloc|kzalloc|kvzalloc").argument(1).l
    case _ =>
      cpg0.call.name("system|open|strcpy|malloc").argument(1).l
  }

  if (debug) {
    System.err.println(s"[c_flow_extract] cwe=$cwe sources=${sources.size} sinks=${sinks.size}")
  }

  val flows = sinks.reachableByFlows(sources).take(maxFlows).l
  flows.foreach { f =>
    val elems = try f.elements.l catch { case _: Throwable => List.empty[Any] }
    val codes = elems.map(nodeCode).map(_.trim).filter(_.nonEmpty).distinct
    val sinkCode = codes.headOption.getOrElse("")
    val srcCode = codes.reverse.find(c => c.nonEmpty && c != sinkCode).getOrElse("")
    val minNodes = if (cwe == "CWE-78") 2 else 3
    if (codes.size >= minNodes && sinkCode.nonEmpty && srcCode.nonEmpty && sinkCode != srcCode) {
      val nodesJson = elems.take(80).map(nodeJson).mkString("[", ",", "]")
      println(s"""{"cwe":"${jesc(cwe)}","origin":"joern_reachableByFlows","sink":"${jesc(sinkCode)}","source":"${jesc(srcCode)}","nodes":${nodesJson},"evidence":${nodesJson}}""")
    }
  }
}
