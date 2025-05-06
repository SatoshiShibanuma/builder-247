import time
import logging
import psutil
import tracemalloc
from typing import Callable, Any

class CleanupPerformanceMonitor:
    """
    A utility class to monitor performance metrics for cleanup jobs.
    
    Tracks execution time, memory usage, and provides logging capabilities.
    """
    
    def __init__(self, logger: logging.Logger = None):
        """
        Initialize the performance monitor.
        
        Args:
            logger (logging.Logger, optional): A logger instance. 
                If not provided, creates a default logger.
        """
        self.logger = logger or logging.getLogger(__name__)
        self.start_time = None
        self.end_time = None
        self.memory_start = None
        self.memory_end = None
        
    def start(self):
        """
        Start performance tracking.
        Begins tracking execution time and memory usage.
        """
        self.start_time = time.time()
        tracemalloc.start()
        self.memory_start = tracemalloc.take_snapshot()
        
    def stop(self):
        """
        Stop performance tracking.
        Records end time and memory snapshot.
        
        Returns:
            dict: Performance metrics including execution time and memory usage.
        """
        self.end_time = time.time()
        self.memory_end = tracemalloc.take_snapshot()
        tracemalloc.stop()
        
        return self.get_metrics()
    
    def get_metrics(self) -> dict:
        """
        Compute and return performance metrics.
        
        Returns:
            dict: Performance metrics including:
                - Total execution time
                - Memory allocation difference
                - Peak memory usage
        """
        if not self.start_time or not self.end_time:
            raise ValueError("Performance tracking not completed. Call start() and stop() first.")
        
        metrics = {
            'execution_time_seconds': self.end_time - self.start_time,
            'peak_memory_usage_bytes': psutil.Process().memory_info().rss
        }
        
        if self.memory_start and self.memory_end:
            top_stats = self.memory_end.compare_to(self.memory_start, 'lineno')
            metrics['memory_allocation'] = sum(stat.size_diff for stat in top_stats)
        
        self.logger.info(f"Cleanup Job Performance Metrics: {metrics}")
        return metrics
    
    def track(self, cleanup_func: Callable[..., Any], *args, **kwargs):
        """
        Decorator-like method to track performance of a cleanup function.
        
        Args:
            cleanup_func (Callable): The cleanup function to monitor
            *args: Positional arguments for the cleanup function
            **kwargs: Keyword arguments for the cleanup function
        
        Returns:
            The result of the cleanup function
        """
        self.start()
        try:
            result = cleanup_func(*args, **kwargs)
            return result
        except Exception as e:
            self.logger.error(f"Cleanup job failed: {e}")
            raise
        finally:
            self.stop()