"""
SecureEvidence: High-Throughput Big Data Processing Service
Author: Nathenael Ermias nathenaelermias13@gmail.com
Specialization: Big Data Engineering (INSA)
"""

from big_data.spark_stream_processor import HighThroughputLogPipeline

class LogStreamService:
    _instance = None

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = HighThroughputLogPipeline(batch_size=2000)
        return cls._instance

    @classmethod
    def get_pipeline(cls):
        return cls.get_instance()

