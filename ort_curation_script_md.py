import yaml
import json
import os
from openai import AzureOpenAI
from datetime import datetime
from typing import Dict, List, Any

class ORTCurationReportGenerator:
    def __init__(self, azure_config: Dict[str, str]):
        """Initialize the Azure OpenAI client."""
        self.client = AzureOpenAI(
            api_version=azure_config['api_version'],
            azure_endpoint=azure_config['endpoint'],
            api_key=azure_config['api_key']
        )
        self.deployment_name = azure_config['deployment_name']
    
    def load_ort_results(self, file_path: str) -> Dict[str, Any]:
        """Load the ORT analyzer results from YAML file."""
        with open(file_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f)
    
    def extract_key_info(self, ort_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract key information from ORT results."""
        analyzer = ort_data.get('analyzer', {})
        result = analyzer.get('result', {})
        repository = ort_data.get('repository', {})
        
        return {
            'repository_url': repository.get('vcs_processed', {}).get('url', 'N/A'),
            'revision': repository.get('vcs_processed', {}).get('revision', 'N/A'),
            'ort_version': analyzer.get('environment', {}).get('ort_version', 'N/A'),
            'scan_time': {
                'start': analyzer.get('start_time', 'N/A'),
                'end': analyzer.get('end_time', 'N/A')
            },
            'projects': result.get('projects', []),
            'packages': result.get('packages', []),
            'issues': result.get('issues', {}),
            'package_managers': analyzer.get('config', {}).get('enabled_package_managers', [])
        }
    
    def determine_analysis_status(self, ort_data: Dict[str, Any]) -> str:
        """Determine if the analysis was successful or had errors."""
        issues = ort_data.get('analyzer', {}).get('result', {}).get('issues', {})
        packages = ort_data.get('analyzer', {}).get('result', {}).get('packages', [])
        
        if issues and len(issues) > 0:
            return "ERROR"
        elif packages and len(packages) > 0:
            return "SUCCESS"
        else:
            return "INCOMPLETE"
    
    def generate_curation_prompt(self, key_info: Dict[str, Any], status: str) -> str:
        """Generate a comprehensive prompt for the LLM."""
        prompt = f"""You are an expert software compliance analyst reviewing ORT (OSS Review Toolkit) analysis results.

**Analysis Status**: {status}

**Repository Information**:
- Repository: {key_info['repository_url']}
- Revision: {key_info['revision']}
- ORT Version: {key_info['ort_version']}

**Scan Details**:
- Start Time: {key_info['scan_time']['start']}
- End Time: {key_info['scan_time']['end']}

**Projects Analyzed**: {len(key_info['projects'])}
**Packages Detected**: {len(key_info['packages'])}
**Issues Found**: {len(key_info['issues'])}

"""
        
        if status == "SUCCESS":
            prompt += """
**Your Task**: Generate a comprehensive curation report in PROPER MARKDOWN FORMAT.

CRITICAL FORMATTING RULES:
- Use proper heading hierarchy: # for main title, ## for sections, ### for subsections
- Add blank lines before and after each heading
- Add blank lines before and after lists
- Use proper markdown list syntax with consistent indentation
- Add blank lines between paragraphs
- Use markdown tables where appropriate
- Use code blocks with ``` for technical content
- Ensure all markdown syntax is properly formatted

**Report Structure** (use this exact structure):

## Executive Summary
[Provide a clear, concise overview]

## License Analysis

### License Distribution
[Create a markdown table showing license types and counts]

### License Categories
[Categorize licenses as Permissive, Copyleft, Proprietary, etc.]

### License Compliance Concerns
[List any concerns with proper formatting]

## Package Inventory

### Package Summary
[Provide statistics]

### Detailed Package List
[Create a well-formatted table or list with: Package Name, Version, License, Source]

## Risk Assessment

### High Priority Issues
[List critical items]

### Medium Priority Issues
[List moderate concerns]

### Low Priority Issues
[List minor notes]

## Recommendations

### Immediate Actions Required
[Numbered list of actions]

### Best Practices
[Bullet list of recommendations]

### Long-term Considerations
[Strategic recommendations]

## Summary

**CRITICAL: Provide a clear, actionable final verdict in this section.**

This section must include:
1. **Overall Project Status**: Clearly state whether the project is "READY TO PROCEED", "NEEDS ATTENTION", or "BLOCKED" for production use
2. **Key Findings**: Summarize the most important points in 2-3 sentences
3. **Compliance Posture**: Assess the overall health of the dependency ecosystem (healthy/moderate concerns/significant risks)
4. **Go/No-Go Recommendation**: Explicitly state if the project can proceed or what must be fixed first

Example format:
"The dependency ecosystem is [healthy/concerning/problematic], with [X] packages using predominantly [permissive/copyleft/mixed] licenses. [No immediate compliance risks identified / Critical issues must be addressed before deployment]. The project is [READY TO PROCEED / REQUIRES REMEDIATION / BLOCKED]."

## Appendix

### Package Details
[Additional technical information]

**Package Information**:
"""
            for pkg in key_info['packages'][:10]:  # Limit to first 10 for prompt size
                prompt += f"\n- {pkg.get('id', 'Unknown')}"
                prompt += f"\n  License: {pkg.get('declared_licenses', ['Unknown'])}"
                prompt += f"\n  Homepage: {pkg.get('homepage_url', 'N/A')}"
                
        else:  # ERROR case
            prompt += """
**Your Task**: Generate an error analysis report in PROPER MARKDOWN FORMAT.

CRITICAL FORMATTING RULES:
- Use proper heading hierarchy: # for main title, ## for sections, ### for subsections
- Add blank lines before and after each heading
- Add blank lines before and after lists
- Use proper markdown list syntax with consistent indentation
- Add blank lines between paragraphs
- Use code blocks with ``` for error messages
- Ensure all markdown syntax is properly formatted

**Report Structure** (use this exact structure):

## Error Summary
[Brief overview of what went wrong]

## Root Cause Analysis

### Primary Error
[Main error explanation]

### Contributing Factors
[List factors that led to the error]

## Detailed Error Information

### Error Messages
[Use code blocks for error messages]

### Affected Components
[List what couldn't be analyzed]

## Impact Assessment

### Compliance Risks
[Explain risks from incomplete analysis]

### Missing Data
[What information is unavailable]

## Troubleshooting Guide

### Immediate Fixes
1. [Step-by-step numbered list]

### Configuration Changes
[Detailed recommendations]

### Alternative Approaches
[Backup strategies]

## Resolution Steps

### Prerequisites
[What needs to be in place]

### Step-by-Step Resolution
1. [Detailed numbered steps]

### Verification
[How to confirm the fix worked]

## Next Steps

### Immediate Actions
- [Prioritized bullet list]

### Follow-up Tasks
- [Additional items]

### Escalation Criteria
[When to escalate]

**Error Details**:
"""
            for project_id, issues in key_info['issues'].items():
                prompt += f"\n\nProject: {project_id}"
                for issue in issues:
                    prompt += f"\n- Severity: {issue.get('severity', 'Unknown')}"
                    prompt += f"\n- Source: {issue.get('source', 'Unknown')}"
                    prompt += f"\n- Message: {issue.get('message', 'Unknown')[:500]}..."
        
        prompt += "\n\nREMEMBER: Strictly follow proper markdown formatting with blank lines, proper heading hierarchy, and consistent indentation. The output must be valid, well-formatted markdown."
        return prompt
    
    def generate_report(self, file_path: str) -> str:
        """Generate the curation report using Azure OpenAI."""
        # Load and parse ORT results
        ort_data = self.load_ort_results(file_path)
        key_info = self.extract_key_info(ort_data)
        status = self.determine_analysis_status(ort_data)
        
        # Create prompt
        prompt = self.generate_curation_prompt(key_info, status)
        
        # Call Azure OpenAI
        response = self.client.chat.completions.create(
            model=self.deployment_name,
            messages=[
                {"role": "system", "content": "You are an expert software compliance analyst specializing in open-source license compliance and dependency analysis. You always produce well-formatted, valid markdown with proper heading hierarchy, blank lines, and consistent formatting."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,
            max_tokens=4000
        )
        
        report = response.choices[0].message.content
        
        # Add metadata header
        metadata = f"""# ORT Analysis Curation Report

**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**Status:** {status}  
**Repository:** {key_info['repository_url']}  
**Revision:** {key_info['revision'][:8]}...

---

"""
        return metadata + report
    
    def save_report(self, report: str, output_path: str):
        """Save the generated report to a file."""
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"Report saved to: {output_path}")


if __name__ == "__main__":
    # Get Azure configuration from environment variables
    azure_config = {
        'endpoint': os.environ.get('AZURE_OPENAI_ENDPOINT', 'https://ltts-cariad-ddd-mvp-ai-foundry.cognitiveservices.azure.com'),
        'api_key': os.environ.get('AZURE_OPENAI_API_KEY'),
        'api_version': '2025-01-01-preview',
        'deployment_name': 'gpt-4.1-mini'
    }
    
    # Validate API key
    if not azure_config['api_key']:
        print("ERROR: AZURE_OPENAI_API_KEY environment variable not set!")
        print("Please set it in your GitHub Secrets.")
        exit(1)
    
    # Initialize generator
    generator = ORTCurationReportGenerator(azure_config)
    
    # Generate report
    input_file = "ort-results/analyzer/analyzer-result.yml"
    output_file = f"curation-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.md"
    
    try:
        report = generator.generate_report(input_file)
        generator.save_report(report, output_file)
        print("\nReport Preview:")
        print("=" * 80)
        print(report[:1000] + "...\n")
        print("=" * 80)
        print(f"\nSuccessfully generated: {output_file}")
    except Exception as e:
        print(f"Error generating report: {str(e)}")
        exit(1)