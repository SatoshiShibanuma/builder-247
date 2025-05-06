import pytest
import time
import logging
from prometheus_swarm.utils.performance_monitor import CleanupPerformanceMonitor

def test_performance_monitor_initialization():
    """Test that performance monitor can be initialized."""
    monitor = CleanupPerformanceMonitor()
    assert monitor is not None
    assert isinstance(monitor.logger, logging.Logger)

def test_performance_monitor_tracking():
    """Test basic performance tracking."""
    monitor = CleanupPerformanceMonitor()
    
    def mock_cleanup_func(duration=0.1):
        time.sleep(duration)
        return "Cleanup Complete"
    
    monitor.start()
    result = mock_cleanup_func()
    metrics = monitor.stop()
    
    assert result == "Cleanup Complete"
    assert 'execution_time_seconds' in metrics
    assert 'peak_memory_usage_bytes' in metrics
    assert metrics['execution_time_seconds'] >= 0.1

def test_performance_monitor_metrics_without_start_stop():
    """Test that getting metrics without start/stop raises an error."""
    monitor = CleanupPerformanceMonitor()
    
    with pytest.raises(ValueError, match="Performance tracking not completed"):
        monitor.get_metrics()

def test_performance_monitor_track_method():
    """Test the track method with a cleanup function."""
    monitor = CleanupPerformanceMonitor()
    
    def mock_cleanup_func(value):
        time.sleep(0.05)
        return value * 2
    
    result = monitor.track(mock_cleanup_func, 5)
    assert result == 10

def test_performance_monitor_track_method_exception():
    """Test the track method handles exceptions."""
    monitor = CleanupPerformanceMonitor()
    
    def failing_cleanup_func():
        raise ValueError("Cleanup failed")
    
    with pytest.raises(ValueError, match="Cleanup failed"):
        monitor.track(failing_cleanup_func)