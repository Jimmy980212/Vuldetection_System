# dataset.py
import os
import glob
import re

class CodeSample:
    """代码样本类"""
    def __init__(self, file_path, code):
        self.file_path = file_path
        self.code = code
        self.file_name = os.path.basename(file_path)
        self.project = os.path.basename(os.path.dirname(file_path))
        self.lines = code.split('\n')
        self.line_count = len(self.lines)

class DatasetLoader:
    """数据集加载器 - 增强版"""
    
    def __init__(self, dataset_dir):
        self.dataset_dir = dataset_dir
        self.samples = []
    
    def load_files(self, extensions=['.c', '.cpp', '.cc', '.h', '.hpp', '.cxx', '.c++', '.java', '.py']):
        """加载目录中的所有代码文件"""
        if not os.path.exists(self.dataset_dir):
            print(f"目录不存在: {self.dataset_dir}")
            return []
        
        file_count = 0
        for ext in extensions:
            pattern = os.path.join(self.dataset_dir, f'**/*{ext}')
            for file_path in glob.glob(pattern, recursive=True):
                code = self._read_file(file_path)
                if code and len(code.strip()) > 10:
                    self.samples.append(CodeSample(file_path, code))
                    file_count += 1
                    
                    if file_count % 10 == 0:
                        print(f"  已加载 {file_count} 个文件...")
        
        print(f"加载 {len(self.samples)} 个代码文件")
        return self.samples
    
    def load_single_file(self, file_path):
        """加载单个代码文件"""
        if not os.path.exists(file_path):
            print(f"文件不存在: {file_path}")
            return None
        
        code = self._read_file(file_path)
        if code:
            sample = CodeSample(file_path, code)
            self.samples = [sample]
            return sample
        return None
    
    def get_statistics(self):
        """获取数据集统计信息"""
        stats = {
            "total_files": len(self.samples),
            "total_lines": sum(s.line_count for s in self.samples),
            "file_types": {},
            "projects": {}
        }
        
        for sample in self.samples:
            ext = os.path.splitext(sample.file_name)[1]
            stats["file_types"][ext] = stats["file_types"].get(ext, 0) + 1
            stats["projects"][sample.project] = stats["projects"].get(sample.project, 0) + 1
        
        return stats
    
    def filter_by_keywords(self, keywords):
        """根据关键字筛选文件"""
        filtered = []
        for sample in self.samples:
            for kw in keywords:
                if kw in sample.code:
                    filtered.append(sample)
                    break
        return filtered
    
    def _read_file(self, file_path):
        """读取文件内容"""
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                return f.read()
        except Exception as e:
            print(f"读取文件失败 {file_path}: {e}")
            return ""