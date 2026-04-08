# core/base.py
from typing import Dict, Any

class BaseAgent:
    """Agent基类"""
    def run(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        执行Agent任务
        :param input_data: 输入数据
        :return: 输出数据
        """
        raise NotImplementedError
