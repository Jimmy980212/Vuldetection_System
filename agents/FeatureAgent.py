# agents/FeatureAgent.py
import os
from typing import Dict, List, Optional
from core.base import BaseAgent

class FeatureAgent(BaseAgent):
    def __init__(self, window_size: int = 20):
        """
        初始化特征提取Agent
        :param window_size: 提取代码切片时的上下文窗口大小（行数）
        """
        super().__init__()
        self.window_size = window_size

    def extract_slice(self, file_path: str, line_num: int) -> str:
        """
        基于行号提取代码上下文切片
        :param file_path: 源文件路径
        :param line_num: 告警行号
        :return: 代码切片字符串
        """
        if not os.path.exists(file_path):
            return f"Error: File not found - {file_path}"

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except Exception as e:
            return f"Error reading file: {str(e)}"

        total_lines = len(lines)
        if total_lines == 0:
            return "Error: File is empty"

        # 计算起止行号 (1-indexed to 0-indexed)
        start = max(0, line_num - self.window_size - 1)
        end = min(total_lines, line_num + self.window_size)

        # 提取切片并加上行号标记
        sliced_lines = []
        for i in range(start, end):
            prefix = "=> " if i == line_num - 1 else "   "
            sliced_lines.append(f"{prefix}{i+1}: {lines[i].rstrip()}")

        return "\n".join(sliced_lines)

    def run(self, input_data: Dict[str, any]) -> Dict[str, any]:
        """
        执行特征提取
        :param input_data: 包含告警信息的输入数据
        :return: 提取的代码特征
        """
        alert = input_data.get("alert")
        
        if not alert:
            return {"sliced_code": "Error: Invalid alert info"}
            
        file_path = alert.get("file")
        line_num = alert.get("line")
        
        if not file_path or not line_num:
            return {"sliced_code": "Error: Invalid alert info"}
            
        sliced_code = self.extract_slice(file_path, int(line_num))
        
        return {
            "sliced_code": sliced_code,
            "file": file_path,
            "line": line_num
        }

if __name__ == "__main__":
    # 测试代码
    agent = FeatureAgent()
    # 假设当前目录下有一个测试文件
    # print(agent.extract_slice("FeatureAgent.py", 10))
    print("FeatureAgent ready.")
