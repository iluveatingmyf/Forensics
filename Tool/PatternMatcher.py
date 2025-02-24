import json
from typing import List, Dict, Any, Tuple, Optional
from datetime import datetime

class PatternMatcher:
    def __init__(self):
        self.patterns = {}  # 存储所有模式及其对应的类型（noise/command）
        
    def add_pattern(self, pattern: List[List[int]], pattern_type: str, name: str = None):
        """
        添加一个模式到匹配器中
        pattern_type: 'noise' 或 'command'
        name: 如果是命令，需要提供命令名称
        """
        # 将模式转换为元组以便哈希
        pattern_tuple = tuple(tuple(p) for p in pattern)
        self.patterns[pattern_tuple] = {
            'type': pattern_type,
            'name': name,
            'length': len(pattern)
        }
        
    def _build_lps(self, pattern: List[List[int]]) -> List[int]:
        """
        构建 KMP 算法的最长公共前缀后缀数组（Longest Proper Prefix which is also Suffix）
        """
        length = 0  # 当前匹配的长度
        lps = [0] * len(pattern)  # lps[i] 存储模式中前i+1个元素的最长公共前后缀长度
        i = 1
        
        while i < len(pattern):
            if pattern[i] == pattern[length]:
                length += 1
                lps[i] = length
                i += 1
            else:
                if length != 0:
                    length = lps[length - 1]
                else:
                    lps[i] = 0
                    i += 1
        return lps
        
    def find_pattern(self, flow_sequence: List[List[int]]) -> List[Dict]:
        """
        在流序列中查找所有匹配的模式
        返回匹配结果列表，每个结果包含模式类型、位置和长度信息
        """
        matches = []
        
        for pattern_tuple, pattern_info in self.patterns.items():
            pattern = list(pattern_tuple)
            pattern_len = len(pattern)
            
            if pattern_len > len(flow_sequence):
                continue
                
            # 构建 LPS 数组
            lps = self._build_lps(pattern)
            
            # KMP 搜索
            i = 0  # flow_sequence 的索引
            j = 0  # pattern 的索引
            
            while i < len(flow_sequence):
                if pattern[j] == flow_sequence[i]:
                    i += 1
                    j += 1
                    
                    if j == pattern_len:
                        matches.append({
                            'type': pattern_info['type'],
                            'name': pattern_info['name'],
                            'start': i - pattern_len,
                            'length': pattern_len
                        })
                        j = lps[j-1]
                elif j > 0:
                    j = lps[j-1]
                else:
                    i += 1
                    
        return matches
