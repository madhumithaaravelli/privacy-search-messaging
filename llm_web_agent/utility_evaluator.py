"""
Utility Evaluator - Compares answer quality, completeness, and latency
across different systems (local vs cloud)
"""

import json
import sys
from typing import Dict, List, Any
from statistics import mean, median
from datetime import datetime


class UtilityEvaluator:
    """Evaluates utility metrics: quality, completeness, latency"""
    
    def __init__(self, results_file: str):
        """
        Initialize evaluator with benchmark results
        
        Args:
            results_file: Path to benchmark_results.json file
        """
        self.results_file = results_file
        with open(results_file, 'r', encoding='utf-8') as f:
            self.data = json.load(f)
        self.system = self.data.get('system', 'unknown')
        self.queries = self.data.get('queries', [])
    
    def calculate_latency_metrics(self) -> Dict[str, float]:
        """Calculate latency statistics"""
        successful_queries = [q for q in self.queries if q.get('success')]
        if not successful_queries:
            return {}
        
        response_times = [q.get('response_time', 0) for q in successful_queries]
        
        return {
            "total_queries": len(self.queries),
            "successful_queries": len(successful_queries),
            "failed_queries": len(self.queries) - len(successful_queries),
            "avg_response_time": mean(response_times),
            "median_response_time": median(response_times),
            "min_response_time": min(response_times),
            "max_response_time": max(response_times),
            "total_time": sum(response_times)
        }
    
    def evaluate_completeness(self) -> Dict[str, Any]:
        """
        Evaluate response completeness
        - Response length (longer = more complete, generally)
        - Whether response addresses the query
        - Presence of sources/citations
        """
        successful_queries = [q for q in self.queries if q.get('success')]
        
        response_lengths = []
        has_sources = 0
        addresses_query = 0
        
        for query_data in successful_queries:
            response = query_data.get('response', '')
            query = query_data.get('query', '')
            
            if response:
                response_lengths.append(len(response))
                
                # Check if response mentions sources/URLs
                if any(indicator in response.lower() for indicator in 
                      ['http', 'www.', 'source', 'according to', 'result']):
                    has_sources += 1
                
                # Simple check: does response contain keywords from query?
                query_words = set(query.lower().split())
                response_lower = response.lower()
                if any(word in response_lower for word in query_words if len(word) > 3):
                    addresses_query += 1
        
        return {
            "avg_response_length": mean(response_lengths) if response_lengths else 0,
            "median_response_length": median(response_lengths) if response_lengths else 0,
            "min_response_length": min(response_lengths) if response_lengths else 0,
            "max_response_length": max(response_lengths) if response_lengths else 0,
            "responses_with_sources": has_sources,
            "responses_addressing_query": addresses_query,
            "completeness_score": (has_sources + addresses_query) / (2 * len(successful_queries)) * 100 
                                  if successful_queries else 0
        }
    
    def evaluate_quality_indicators(self) -> Dict[str, Any]:
        """
        Evaluate quality indicators
        - Response structure (well-formed)
        - Information density
        - Error handling
        """
        successful_queries = [q for q in self.queries if q.get('success')]
        
        well_formed = 0
        has_details = 0
        error_responses = 0
        
        for query_data in successful_queries:
            response = query_data.get('response', '')
            
            if not response:
                continue
            
            # Well-formed: has structure (sentences, paragraphs)
            if len(response.split('.')) > 2:  # Multiple sentences
                well_formed += 1
            
            # Has details: contains specific information (numbers, dates, names)
            if any(char.isdigit() for char in response):
                has_details += 1
            
            # Error responses: contains apology/error messages
            error_keywords = ['sorry', 'unable', 'cannot', 'error', 'apologize']
            if any(keyword in response.lower() for keyword in error_keywords):
                error_responses += 1
        
        return {
            "well_formed_responses": well_formed,
            "responses_with_details": has_details,
            "error_responses": error_responses,
            "quality_score": ((well_formed + has_details) / (2 * len(successful_queries)) * 100 
                            if successful_queries else 0) - (error_responses / len(successful_queries) * 10 
                            if successful_queries else 0)
        }
    
    def get_utility_metrics(self) -> Dict[str, Any]:
        """Get all utility metrics"""
        return {
            "system": self.system,
            "latency": self.calculate_latency_metrics(),
            "completeness": self.evaluate_completeness(),
            "quality": self.evaluate_quality_indicators()
        }
    
    def export_report(self, output_file: str = None) -> Dict[str, Any]:
        """Export utility evaluation report"""
        if output_file is None:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            output_file = f"utility_report_{self.system}_{timestamp}.json"
        
        report = {
            "evaluation_date": datetime.now().isoformat(),
            "results_file": self.results_file,
            "utility_metrics": self.get_utility_metrics()
        }
        
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        
        return report


def compare_utility(local_file: str, cloud_files: List[str]) -> Dict[str, Any]:
    """
    Compare utility metrics across systems
    
    Args:
        local_file: Path to local benchmark results
        cloud_files: List of paths to cloud benchmark results
    """
    local_eval = UtilityEvaluator(local_file)
    cloud_evals = [UtilityEvaluator(f) for f in cloud_files]
    
    comparison = {
        "comparison_date": datetime.now().isoformat(),
        "local_system": local_eval.get_utility_metrics(),
        "cloud_systems": {}
    }
    
    for cloud_eval in cloud_evals:
        comparison["cloud_systems"][cloud_eval.system] = cloud_eval.get_utility_metrics()
    
    # Calculate differences
    local_latency = local_eval.calculate_latency_metrics()
    local_completeness = local_eval.evaluate_completeness()
    local_quality = local_eval.evaluate_quality_indicators()
    
    comparison["key_differences"] = {}
    
    for cloud_eval in cloud_evals:
        cloud_latency = cloud_eval.calculate_latency_metrics()
        cloud_completeness = cloud_eval.evaluate_completeness()
        cloud_quality = cloud_eval.evaluate_quality_indicators()
        
        comparison["key_differences"][cloud_eval.system] = {
            "latency": {
                "local_avg": local_latency.get("avg_response_time", 0),
                "cloud_avg": cloud_latency.get("avg_response_time", 0),
                "difference": cloud_latency.get("avg_response_time", 0) - local_latency.get("avg_response_time", 0),
                "local_faster": local_latency.get("avg_response_time", 0) < cloud_latency.get("avg_response_time", 0),
                "speedup_factor": local_latency.get("avg_response_time", 0) / cloud_latency.get("avg_response_time", 0) 
                                 if cloud_latency.get("avg_response_time", 0) > 0 else 0
            },
            "completeness": {
                "local_score": local_completeness.get("completeness_score", 0),
                "cloud_score": cloud_completeness.get("completeness_score", 0),
                "local_avg_length": local_completeness.get("avg_response_length", 0),
                "cloud_avg_length": cloud_completeness.get("avg_response_length", 0)
            },
            "quality": {
                "local_score": local_quality.get("quality_score", 0),
                "cloud_score": cloud_quality.get("quality_score", 0)
            }
        }
    
    return comparison


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python utility_evaluator.py <results_file> [compare_file1] [compare_file2] ...")
        print("\nExamples:")
        print("  # Evaluate single system:")
        print("  python utility_evaluator.py benchmark_results.json")
        print("\n  # Compare systems:")
        print("  python utility_evaluator.py benchmark_results.json \\")
        print("    benchmark_results_cloud_google_*.json \\")
        print("    benchmark_results_cloud_openai_*.json")
        sys.exit(1)
    
    local_file = sys.argv[1]
    cloud_files = sys.argv[2:] if len(sys.argv) > 2 else []
    
    if cloud_files:
        # Compare mode
        comparison = compare_utility(local_file, cloud_files)
        
        output_file = f"utility_comparison_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(comparison, f, indent=2)
        
        print("=" * 70)
        print("UTILITY COMPARISON")
        print("=" * 70)
        print()
        
        local_metrics = comparison["local_system"]
        print(f"LOCAL SYSTEM ({local_metrics['system']}):")
        print(f"  Avg Response Time: {local_metrics['latency']['avg_response_time']:.2f}s")
        print(f"  Completeness Score: {local_metrics['completeness']['completeness_score']:.1f}%")
        print(f"  Quality Score: {local_metrics['quality']['quality_score']:.1f}%")
        print()
        
        for cloud_name, cloud_metrics in comparison["cloud_systems"].items():
            print(f"CLOUD SYSTEM ({cloud_name}):")
            print(f"  Avg Response Time: {cloud_metrics['latency']['avg_response_time']:.2f}s")
            print(f"  Completeness Score: {cloud_metrics['completeness']['completeness_score']:.1f}%")
            print(f"  Quality Score: {cloud_metrics['quality']['quality_score']:.1f}%")
            print()
            
            diff = comparison["key_differences"][cloud_name]
            print(f"COMPARISON (Local vs {cloud_name}):")
            latency_diff = diff["latency"]["difference"]
            speedup = diff["latency"]["speedup_factor"]
            if latency_diff < 0:
                print(f"  Latency: Cloud is {abs(latency_diff):.2f}s FASTER ({speedup:.1f}x faster)")
            else:
                print(f"  Latency: Local is {latency_diff:.2f}s FASTER ({1/speedup:.1f}x faster)" if speedup > 0 else "  Latency: N/A")
            print(f"  Completeness: Local {diff['completeness']['local_score']:.1f}% vs Cloud {diff['completeness']['cloud_score']:.1f}%")
            print(f"  Quality: Local {diff['quality']['local_score']:.1f}% vs Cloud {diff['quality']['cloud_score']:.1f}%")
            print()
        
        print(f"Full comparison saved to: {output_file}")
    else:
        # Single system evaluation
        evaluator = UtilityEvaluator(local_file)
        report = evaluator.export_report()
        
        metrics = report["utility_metrics"]
        print("=" * 70)
        print(f"UTILITY EVALUATION: {metrics['system'].upper()}")
        print("=" * 70)
        print()
        print("LATENCY:")
        latency = metrics['latency']
        print(f"  Total Queries: {latency['total_queries']}")
        print(f"  Successful: {latency['successful_queries']}")
        print(f"  Failed: {latency['failed_queries']}")
        print(f"  Avg Response Time: {latency['avg_response_time']:.2f}s")
        print(f"  Median Response Time: {latency['median_response_time']:.2f}s")
        print(f"  Min: {latency['min_response_time']:.2f}s, Max: {latency['max_response_time']:.2f}s")
        print()
        print("COMPLETENESS:")
        completeness = metrics['completeness']
        print(f"  Avg Response Length: {completeness['avg_response_length']:.0f} characters")
        print(f"  Responses with Sources: {completeness['responses_with_sources']}/{latency['successful_queries']}")
        print(f"  Completeness Score: {completeness['completeness_score']:.1f}%")
        print()
        print("QUALITY:")
        quality = metrics['quality']
        print(f"  Well-formed Responses: {quality['well_formed_responses']}/{latency['successful_queries']}")
        print(f"  Responses with Details: {quality['responses_with_details']}/{latency['successful_queries']}")
        print(f"  Quality Score: {quality['quality_score']:.1f}%")
        print()
        print(f"Report saved to: {report}")

