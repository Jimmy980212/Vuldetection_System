# utils/code_parser.py
import re
from typing import List, Dict, Tuple

class CodeParser:
    """代码解析工具"""
    
    @staticmethod
    def extract_function(code: str, line_number: int) -> str:
        """
        提取包含指定行号的函数
        :param code: 代码内容
        :param line_number: 行号
        :return: 函数代码
        """
        lines = code.split('\n')
        if line_number <= 0 or line_number > len(lines):
            return ""
        
        # 查找函数开始
        start_line = line_number - 1
        while start_line >= 0:
            line = lines[start_line].strip()
            if re.match(r'\w+\s+\w+\s*\([^)]*\)\s*\{', line):
                break
            start_line -= 1
        
        if start_line < 0:
            return ""
        
        # 查找函数结束
        end_line = line_number - 1
        brace_count = 0
        for i in range(start_line, len(lines)):
            line = lines[i]
            brace_count += line.count('{') - line.count('}')
            if brace_count == 0:
                end_line = i
                break
        
        return '\n'.join(lines[start_line:end_line+1])
    
    @staticmethod
    def find_source_sink_pairs(code: str) -> List[Tuple[int, int]]:
        """
        查找代码中的source-sink对
        :param code: 代码内容
        :return: (source行号, sink行号)列表
        """
        lines = code.split('\n')
        source_lines = []
        sink_lines = []
        
        # 常见的source函数
        source_patterns = [
            r'gets\s*\(',
            r'scanf\s*\(',
            r'fgets\s*\(',
            r'read\s*\(',
            r'recv\s*\(',
            r'getenv\s*\('
        ]
        
        # 常见的sink函数
        sink_patterns = [
            r'strcpy\s*\(',
            r'strcat\s*\(',
            r'printf\s*\(',
            r'fprintf\s*\(',
            r'system\s*\(',
            r'exec\w*\s*\(',
            r'malloc\s*\(',
            r'free\s*\('
        ]
        
        for i, line in enumerate(lines):
            for pattern in source_patterns:
                if re.search(pattern, line):
                    source_lines.append(i + 1)
                    break
            
            for pattern in sink_patterns:
                if re.search(pattern, line):
                    sink_lines.append(i + 1)
                    break
        
        # 简单的source-sink配对
        pairs = []
        for source in source_lines:
            for sink in sink_lines:
                if sink > source:
                    pairs.append((source, sink))
        
        return pairs
    
    @staticmethod
    def generate_control_flow(code: str) -> Dict[str, List[int]]:
        """
        生成简单的控制流图
        :param code: 代码内容
        :return: 控制流字典
        """
        lines = code.split('\n')
        control_flow = {}
        
        for i, line in enumerate(lines):
            current_line = i + 1
            control_flow[current_line] = []
            
            # 简单的控制流分析
            stripped_line = line.strip()
            
            # 条件语句
            if re.match(r'if\s*\([^)]*\)\s*\{?', stripped_line):
                # 假设下一行是条件体的开始
                if current_line < len(lines):
                    control_flow[current_line].append(current_line + 1)
            
            # 循环语句
            elif re.match(r'for\s*\([^)]*\)\s*\{?', stripped_line) or \
                 re.match(r'while\s*\([^)]*\)\s*\{?', stripped_line):
                # 假设下一行是循环体的开始
                if current_line < len(lines):
                    control_flow[current_line].append(current_line + 1)
            
            # 正常流程
            if current_line < len(lines):
                control_flow[current_line].append(current_line + 1)
        
        return control_flow
