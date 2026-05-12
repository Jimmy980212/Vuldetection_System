"""
huggingface_dataset_mirror.py - 从HuggingFace加载测试文件的代码（支持国内镜像源）
模仿system_2中的数据加载模式，为system_4添加HuggingFace数据集支持
支持使用hf-mirror.com国内镜像源
"""
import os
import json
import random
import hashlib
import logging
from typing import List, Dict, Optional
from pathlib import Path
import pandas as pd
from datetime import datetime

# 导入 system_4 配置（会默认启用 HF 国内镜像；见 config.apply_hf_mirror）
from config import (
    DATASET_DIR,
    RESULT_DIR,
    TEMP_DIR,
    apply_hf_mirror,
    PRIMEVUL_HF_DATASET,
    PRIMEVUL_HF_CONFIG,
)

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(os.path.join(RESULT_DIR, 'huggingface_dataset_mirror.log')),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class HuggingFaceDatasetLoader:
    """HuggingFace数据集加载器 - 支持国内镜像源"""
    
    def __init__(self, cache_dir: str = None, use_cache: bool = True, use_mirror: bool = True):
        self.cache_dir = cache_dir or os.path.join(DATASET_DIR, "cache")
        self.use_cache = use_cache
        self.use_mirror = use_mirror
        self.dataset = []
        self.cache_file = os.path.join(self.cache_dir, "huggingface_cache.json")
        self.stats = {
            'total': 0,
            'vulnerable': 0,
            'non_vulnerable': 0,
            'cwe_distribution': {},
            'project_distribution': {}
        }
        
        os.makedirs(self.cache_dir, exist_ok=True)
        
        if use_cache and os.path.exists(self.cache_file):
            self._load_cache()
    
    def load_secvuleval_dataset(self, split: str = "train", limit: int = None) -> List[Dict]:
        """从HuggingFace加载SecVulEval数据集，支持国内镜像源"""
        logger.info(f"从HuggingFace加载SecVulEval数据集 (split={split})...")
        
        try:
            apply_hf_mirror(self.use_mirror)
            if self.use_mirror:
                logger.info("使用 HuggingFace 国内镜像: %s", os.environ.get("HF_ENDPOINT"))
            else:
                logger.info("使用 HuggingFace 官方 Hub: %s", os.environ.get("HF_ENDPOINT"))

            from datasets import load_dataset
            
            # 加载数据集
            dataset = load_dataset("SecVulEval", split=split)
            logger.info(f"成功加载数据集，共 {len(dataset)} 个样本")
            
            # 转换为列表
            self.dataset = []
            for i, item in enumerate(dataset):
                sample = self._convert_to_dict(item)
                self.dataset.append(sample)
                
                if limit and i >= limit - 1:
                    break
            
            self._update_stats()
            
            if self.use_cache:
                self._save_cache()
            
            return self.dataset
            
        except Exception as e:
            logger.error(f"加载失败: {e}")
            logger.warning("使用模拟数据集...")
            return self._create_mock_dataset(size=limit or 50)

    def _primevul_row_to_unified(self, row: Dict, seq: int) -> Dict:
        """PrimeVul 行 -> 与 SecVulEval 适配器统一的字典（func_body / is_vulnerable 等）。"""
        code = (row.get("func") or "").strip()
        target = row.get("target")
        is_vuln = target == 1
        idx = row.get("idx", seq)
        proj = (row.get("project") or "unknown").replace("/", "_").replace("\\", "_")
        fname = f"pv_{idx}_{proj}.c"
        cwe = row.get("cwe") or []
        if isinstance(cwe, str):
            cwe = [cwe]
        return {
            "func_body": code,
            "func_name": f"pv_{idx}",
            "is_vulnerable": is_vuln,
            "cwe_list": list(cwe) if cwe else [],
            "project": row.get("project") or "unknown",
            "idx": idx,
            "file_name": fname,
        }

    def load_primevul_balanced(
        self,
        total: int,
        vuln_ratio: float = 0.5,
        split: str = "train",
        seed: int = 42,
        max_scan: int = 500000,
    ) -> List[Dict]:
        """
        从 PrimeVul 流式扫描，按漏洞/安全比例各取若干条（适合大数据集，不必整表载入内存）。
        """
        apply_hf_mirror(self.use_mirror)
        random.seed(seed)
        need_v = max(0, int(round(total * vuln_ratio)))
        need_s = max(0, total - need_v)
        logger.info(
            "从 PrimeVul 均衡采样: total=%s vuln=%s safe=%s split=%s",
            total,
            need_v,
            need_s,
            split,
        )
        vuln_pool: List[Dict] = []
        safe_pool: List[Dict] = []
        try:
            from datasets import load_dataset

            ds = load_dataset(
                PRIMEVUL_HF_DATASET,
                PRIMEVUL_HF_CONFIG,
                split=split,
                streaming=True,
            )
            scanned = 0
            for row in ds:
                scanned += 1
                if scanned > max_scan:
                    logger.warning("PrimeVul 扫描达到上限 max_scan=%s，停止收集", max_scan)
                    break
                d = self._convert_to_dict(row)
                func = (d.get("func") or "").strip()
                if len(func) < 20:
                    continue
                t = d.get("target")
                if t == 1 and len(vuln_pool) < max(need_v * 4, need_v + 5):
                    vuln_pool.append(d)
                elif t == 0 and len(safe_pool) < max(need_s * 4, need_s + 5):
                    safe_pool.append(d)
                if len(vuln_pool) >= need_v and len(safe_pool) >= need_s:
                    break

            if len(vuln_pool) < need_v or len(safe_pool) < need_s:
                logger.warning(
                    "PrimeVul 可用样本不足: 需要 vuln=%s safe=%s，实际 vuln=%s safe=%s",
                    need_v,
                    need_s,
                    len(vuln_pool),
                    len(safe_pool),
                )

            random.shuffle(vuln_pool)
            random.shuffle(safe_pool)
            take_v = min(need_v, len(vuln_pool))
            take_s = min(need_s, len(safe_pool))
            selected_rows = vuln_pool[:take_v] + safe_pool[:take_s]
            random.shuffle(selected_rows)

            out: List[Dict] = []
            for i, r in enumerate(selected_rows):
                out.append(self._primevul_row_to_unified(r, i))
            self.dataset = out
            self._update_stats()
            logger.info("PrimeVul 采样完成: %s 条", len(out))
            return out
        except Exception as e:
            logger.error("加载 PrimeVul 失败: %s", e)
            return []

    def _convert_to_dict(self, item) -> Dict:
        """将HuggingFace item转换为字典"""
        result = {}
        for key in item.keys():
            value = item[key]
            # 处理特殊类型
            if hasattr(value, 'as_py'):
                value = value.as_py()
            result[key] = value
        return result
    
    def _create_mock_dataset(self, size: int = 50) -> List[Dict]:
        """创建模拟数据集用于测试"""
        self.dataset = []
        
        for i in range(size):
            is_vuln = i % 3 != 0  # 约2/3为漏洞样本
            cwe_list = self._get_random_cwe() if is_vuln else []
            
            sample = {
                'idx': i,
                'func_name': f'func_{i}',
                'project': random.choice(['linux', 'openssl', 'nginx', 'redis', 'mysql']),
                'filepath': f'src/file_{i % 10}.c',
                'is_vulnerable': is_vuln,
                'func_body': self._get_mock_code(is_vuln, i),
                'cwe_list': cwe_list,
            }
            self.dataset.append(sample)
        
        logger.info(f"创建 {len(self.dataset)} 个模拟样本")
        self._update_stats()
        return self.dataset
    
    def _get_random_cwe(self) -> List[str]:
        """随机获取CWE列表"""
        common_cwes = ['CWE-119', 'CWE-416', 'CWE-476', 'CWE-190', 'CWE-78', 'CWE-134']
        return random.sample(common_cwes, random.randint(1, 2))
    
    def _get_mock_code(self, is_vuln: bool, idx: int) -> str:
        """获取模拟代码"""
        if is_vuln:
            vuln_types = [
                '''void vulnerable_func(char *input) {
    char buffer[64];
    strcpy(buffer, input);
    printf("Input: %s\\n", buffer);
}''',
                '''void use_after_free() {
    int *ptr = (int*)malloc(sizeof(int) * 10);
    free(ptr);
    *ptr = 42;
}''',
                '''void null_pointer() {
    int *ptr = NULL;
    *ptr = 10;
}'''
            ]
            return vuln_types[idx % len(vuln_types)]
        else:
            return '''void safe_function(char *input) {
    char buffer[64];
    strncpy(buffer, input, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\\0';
    printf("Input: %s\\n", buffer);
}'''
    
    def _update_stats(self):
        """更新统计信息"""
        self.stats['total'] = len(self.dataset)
        self.stats['vulnerable'] = sum(1 for s in self.dataset if s.get('is_vulnerable', False))
        self.stats['non_vulnerable'] = self.stats['total'] - self.stats['vulnerable']
        
        # CWE分布
        cwe_counter = {}
        for sample in self.dataset:
            for cwe in sample.get('cwe_list', []):
                cwe_counter[cwe] = cwe_counter.get(cwe, 0) + 1
        self.stats['cwe_distribution'] = cwe_counter
        
        # 项目分布
        project_counter = {}
        for sample in self.dataset:
            project = sample.get('project', 'unknown')
            project_counter[project] = project_counter.get(project, 0) + 1
        self.stats['project_distribution'] = project_counter
    
    def _load_cache(self):
        """加载缓存"""
        try:
            with open(self.cache_file, 'r', encoding='utf-8') as f:
                cache = json.load(f)
                self.dataset = cache.get('dataset', [])
                self.stats = cache.get('stats', {})
                logger.info(f"加载缓存: {len(self.dataset)} 个样本")
        except Exception as e:
            logger.warning(f"缓存加载失败: {e}")
            self.dataset = []
    
    def _save_cache(self):
        """保存缓存"""
        try:
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'dataset': self.dataset,
                    'stats': self.stats,
                    'timestamp': datetime.now().isoformat()
                }, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.warning(f"缓存保存失败: {e}")
    
    def get_vulnerable_samples(self, limit: int = None) -> List[Dict]:
        """获取漏洞样本"""
        vulnerable = [s for s in self.dataset if s.get('is_vulnerable', False)]
        
        if limit:
            vulnerable = vulnerable[:min(limit, len(vulnerable))]
        
        return vulnerable
    
    def get_non_vulnerable_samples(self, limit: int = None) -> List[Dict]:
        """获取非漏洞样本"""
        non_vuln = [s for s in self.dataset if not s.get('is_vulnerable', False)]
        
        if limit:
            non_vuln = non_vuln[:min(limit, len(non_vuln))]
        
        return non_vuln
    
    def extract_function_code(self, sample: Dict) -> str:
        """提取函数代码"""
        return sample.get('func_body', '')
    
    def create_temp_file(self, sample: Dict) -> str:
        """创建临时文件"""
        func_body = self.extract_function_code(sample)
        idx = sample.get('idx', 0)
        func_name = sample.get('func_name', f'func_{idx}')
        
        # 生成文件哈希作为唯一标识
        content_hash = hashlib.md5(func_body.encode()).hexdigest()[:8]
        file_path = os.path.join(TEMP_DIR, f"hf_sample_{idx}_{func_name}_{content_hash}.c")
        
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(func_body)
        
        return file_path
    
    def get_statistics(self) -> Dict:
        """获取数据集统计信息"""
        return self.stats
    
    def print_statistics(self):
        """打印统计信息"""
        print("\n" + "=" * 60)
        print("HuggingFace数据集统计信息")
        print("=" * 60)
        print(f"总样本数: {self.stats['total']}")
        print(f"漏洞样本: {self.stats['vulnerable']} ({self.stats['vulnerable']/self.stats['total']*100:.1f}%)")
        print(f"安全样本: {self.stats['non_vulnerable']} ({self.stats['non_vulnerable']/self.stats['total']*100:.1f}%)")
        
        print("\nCWE分布:")
        for cwe, count in sorted(self.stats['cwe_distribution'].items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"  {cwe}: {count}")
        
        print("\n项目分布:")
        for project, count in sorted(self.stats['project_distribution'].items(), key=lambda x: x[1], reverse=True)[:10]:
            print(f"  {project}: {count}")
        print("=" * 60)


class System4DatasetAdapter:
    """system_4数据集适配器 - 将HuggingFace数据集成到system_4"""
    
    def __init__(self, use_huggingface: bool = True, use_mirror: bool = True):
        self.use_huggingface = use_huggingface
        self.use_mirror = use_mirror
        self.hf_loader = HuggingFaceDatasetLoader(use_mirror=use_mirror) if use_huggingface else None
        self.samples = []
    
    def load_samples(self, limit: int = 20, from_huggingface: bool = True, split: str = "train"):
        """加载样本，支持从HuggingFace或本地加载"""
        if from_huggingface and self.use_huggingface:
            logger.info("从HuggingFace加载样本...")
            hf_samples = self.hf_loader.load_secvuleval_dataset(split=split, limit=limit)
            
            # 转换为system_4的CodeSample格式
            self.samples = []
            for i, hf_sample in enumerate(hf_samples):
                code = hf_sample.get('func_body', '')
                if code:
                    # 创建虚拟文件路径
                    project = hf_sample.get('project', 'huggingface')
                    func_name = hf_sample.get('func_name', f'func_{i}')
                    file_path = f"{project}/{func_name}.c"
                    
                    # 创建类似dataset.py中的CodeSample对象
                    class CodeSample:
                        def __init__(self, file_path, code):
                            self.file_path = file_path
                            self.code = code
                            self.file_name = os.path.basename(file_path)
                            self.project = os.path.basename(os.path.dirname(file_path))
                            self.lines = code.split('\n')
                            self.line_count = len(self.lines)
                            # 添加HuggingFace数据
                            self.hf_data = hf_sample
                            self.is_vulnerable = hf_sample.get('is_vulnerable', False)
                            self.cwe_list = hf_sample.get('cwe_list', [])
                    
                    sample = CodeSample(file_path, code)
                    self.samples.append(sample)
            
            logger.info(f"从HuggingFace加载 {len(self.samples)} 个样本")
            return self.samples
        else:
            # 本地文件加载逻辑（可以调用原有的dataset.py）
            logger.info("从本地文件加载样本...")
            # 这里可以集成原有的dataset.py逻辑
            return []

    def load_secvul_balanced(
        self,
        total_samples: int = 20,
        vuln_ratio: float = 0.5,
        split: str = "train",
        seed: int = 42,
        overfetch_factor: int = 8,
    ):
        """从 SecVulEval 按漏洞/安全比例采样，转为 CodeSample 列表。"""
        if not self.use_huggingface or not self.hf_loader:
            logger.warning("未启用 HuggingFace 加载器，无法加载 SecVulEval")
            return []

        total_samples = max(1, int(total_samples))
        vuln_ratio = max(0.0, min(1.0, float(vuln_ratio)))
        random.seed(seed)

        need_v = int(round(total_samples * vuln_ratio))
        need_s = total_samples - need_v

        # SecVulEval 当前为非流式加载，使用 overfetch 控制载入规模，避免整表拉取过大。
        fetch_limit = max(total_samples, total_samples * max(1, int(overfetch_factor)))
        rows = self.hf_loader.load_secvuleval_dataset(split=split, limit=fetch_limit)

        vuln_pool = [r for r in rows if bool(r.get("is_vulnerable", False))]
        safe_pool = [r for r in rows if not bool(r.get("is_vulnerable", False))]
        random.shuffle(vuln_pool)
        random.shuffle(safe_pool)

        selected = vuln_pool[: min(need_v, len(vuln_pool))] + safe_pool[: min(need_s, len(safe_pool))]
        random.shuffle(selected)

        if len(selected) < total_samples:
            logger.warning(
                "SecVulEval 样本不足: 需要 total=%s(v=%s,s=%s)，实际可用 v=%s s=%s，最终=%s",
                total_samples,
                need_v,
                need_s,
                len(vuln_pool),
                len(safe_pool),
                len(selected),
            )

        self.samples = []
        for i, hf_sample in enumerate(selected):
            code = hf_sample.get("func_body", "")
            if not code.strip():
                continue
            project = hf_sample.get("project", "unknown")
            func_name = hf_sample.get("func_name", f"secvul_{i}")
            file_path = f"{project}/{func_name}.c"

            class CodeSample:
                def __init__(self, fp, c, meta):
                    self.file_path = fp
                    self.code = c
                    self.file_name = os.path.basename(fp)
                    self.project = meta.get("project") or os.path.basename(os.path.dirname(fp))
                    self.lines = c.split("\n")
                    self.line_count = len(self.lines)
                    self.hf_data = meta
                    self.is_vulnerable = bool(meta.get("is_vulnerable", False))
                    self.cwe_list = meta.get("cwe_list", [])
                    self.idx = meta.get("idx", -1)

            self.samples.append(CodeSample(file_path, code, hf_sample))

        logger.info(
            "SecVulEval 按比例采样完成: total=%s vuln_ratio=%.3f 实际=%s",
            total_samples,
            vuln_ratio,
            len(self.samples),
        )
        return self.samples

    def load_primevul_balanced(
        self,
        total_samples: int = 20,
        vuln_ratio: float = 0.5,
        split: str = "train",
        seed: int = 42,
    ):
        """从 HuggingFace PrimeVul（镜像）均衡加载，转为 CodeSample 列表。"""
        if not self.use_huggingface or not self.hf_loader:
            logger.warning("未启用 HuggingFace 加载器，无法加载 PrimeVul")
            return []
        rows = self.hf_loader.load_primevul_balanced(
            total_samples, vuln_ratio, split=split, seed=seed
        )
        self.samples = []
        for i, hf_sample in enumerate(rows):
            code = hf_sample.get("func_body", "")
            if not code.strip():
                continue
            project = hf_sample.get("project", "unknown")
            file_path = f"{project}/{hf_sample.get('file_name', f'pv_{i}.c')}"
            seq_i = i

            class CodeSample:
                def __init__(self, fp, c, meta, _seq):
                    self.file_path = fp
                    self.code = c
                    self.file_name = meta.get("file_name") or os.path.basename(fp)
                    self.project = meta.get("project") or "unknown"
                    self.lines = c.split("\n")
                    self.line_count = len(self.lines)
                    self.hf_data = meta
                    self.is_vulnerable = bool(meta.get("is_vulnerable", False))
                    self.cwe_list = meta.get("cwe_list", [])
                    self.idx = meta.get("idx", _seq)

            sample = CodeSample(file_path, code, hf_sample, seq_i)
            self.samples.append(sample)

        logger.info(f"PrimeVul 转为 CodeSample: {len(self.samples)} 条")
        return self.samples

    def get_vulnerable_samples(self, limit: int = None):
        """获取漏洞样本"""
        if not self.use_huggingface:
            return []
        
        vulnerable = [s for s in self.samples if hasattr(s, 'is_vulnerable') and s.is_vulnerable]
        
        if limit:
            vulnerable = vulnerable[:min(limit, len(vulnerable))]
        
        return vulnerable
    
    def create_test_files(self, output_dir: str = None):
        """创建测试文件到指定目录"""
        if not output_dir:
            output_dir = os.path.join(DATASET_DIR, "huggingface_samples")
        
        os.makedirs(output_dir, exist_ok=True)
        
        for i, sample in enumerate(self.samples):
            file_name = f"hf_sample_{i}_{sample.file_name}"
            file_path = os.path.join(output_dir, file_name)
            
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(sample.code)
            
            logger.info(f"创建测试文件: {file_path}")
        
        logger.info(f"共创建 {len(self.samples)} 个测试文件到 {output_dir}")
        return output_dir


# 测试函数
def test_huggingface_loader_with_mirror():
    """测试HuggingFace数据加载器（使用镜像源）"""
    print("测试HuggingFace数据加载器（使用国内镜像源）...")
    
    # 创建加载器（使用镜像源）
    loader = HuggingFaceDatasetLoader(use_mirror=True)
    
    # 加载数据
    samples = loader.load_secvuleval_dataset(limit=10)
    print(f"加载了 {len(samples)} 个样本")
    
    # 打印统计信息
    loader.print_statistics()
    
    # 测试适配器
    adapter = System4DatasetAdapter(use_mirror=True)
    adapter_samples = adapter.load_samples(limit=5)
    print(f"适配器加载了 {len(adapter_samples)} 个样本")
    
    # 创建测试文件
    output_dir = adapter.create_test_files()
    print(f"测试文件已创建到: {output_dir}")
    
    print("测试完成！")


def test_mirror_connection():
    """测试镜像源连接"""
    print("测试HuggingFace国内镜像源连接...")
    print("=" * 60)
    
    original_hf_endpoint = os.environ.get("HF_ENDPOINT", "")
    original_hub_ep = os.environ.get("HUGGINGFACE_HUB_ENDPOINT", "")
    apply_hf_mirror(True)
    
    try:
        from datasets import load_dataset
        
        print("尝试连接HuggingFace镜像源...")
        # 尝试加载一个小数据集来测试连接
        dataset = load_dataset("SecVulEval", split="train[:5]")
        print(f"✅ 镜像源连接成功！加载了 {len(dataset)} 个样本")
        
        # 显示样本信息
        print("\n样本信息:")
        for i in range(min(3, len(dataset))):
            item = dataset[i]
            print(f"  样本 {i+1}: {item.get('func_name', 'unknown')}")
        
        return True
    except Exception as e:
        print(f"❌ 镜像源连接失败: {e}")
        return False
    finally:
        if original_hf_endpoint:
            os.environ["HF_ENDPOINT"] = original_hf_endpoint
        else:
            os.environ.pop("HF_ENDPOINT", None)
        if original_hub_ep:
            os.environ["HUGGINGFACE_HUB_ENDPOINT"] = original_hub_ep
        else:
            os.environ.pop("HUGGINGFACE_HUB_ENDPOINT", None)


if __name__ == "__main__":
    print("HuggingFace数据加载器测试（支持国内镜像源）")
    print("=" * 60)
    
    # 测试镜像源连接
    connection_ok = test_mirror_connection()
    
    if connection_ok:
        # 测试完整功能
        test_huggingface_loader_with_mirror()
    else:
        print("\n⚠️  镜像源连接失败，使用模拟数据进行测试...")
        # 使用模拟数据测试
        loader = HuggingFaceDatasetLoader(use_mirror=False)
        samples = loader.load_secvuleval_dataset(limit=5)
        print(f"使用模拟数据加载了 {len(samples)} 个样本")
        loader.print_statistics()