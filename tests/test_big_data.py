"""
Unit Tests for High-Throughput Big Data Stream Processor
Author: Nathenael Ermias nathenaelermias13@gmail.com
"""

import pytest
from big_data.spark_stream_processor import HighThroughputLogPipeline
from big_data.stream_simulator import stream_events

def test_big_data_pipeline_batch():
    """Verify batch processing throughput and anomaly counting."""
    pipeline = HighThroughputLogPipeline(batch_size=100)
    events = list(stream_events(count=50, delay_sec=0))
    
    assert len(events) == 50
    summary = pipeline.process_event_batch(events)
    
    assert summary["batch_size"] == 50
    assert summary["throughput_events_per_sec"] > 0
    assert "threats_detected_count" in summary
    assert "asset_distribution" in summary
    assert "Nathenael Ermias" in summary["author_credit"]
