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
**Your Task**: Generate a comprehensive curation report in CLEAN HTML FORMAT (content only, NO <html>, <head>, or <body> tags).

CRITICAL FORMATTING RULES:
- Return ONLY the content HTML (divs, headings, paragraphs, tables, lists)
- Do NOT include <html>, <head>, <body>, <!DOCTYPE>, or <style> tags
- Use semantic HTML5 elements: <section>, <article>, <h1>-<h6>, <p>, <table>, <ul>, <ol>
- Use class names for styling: 'section', 'subsection', 'summary-box', 'status-badge', 'data-table', 'risk-high', 'risk-medium', 'risk-low'
- Create responsive, well-structured HTML tables with <thead> and <tbody>
- Use <code> tags for technical content
- Use appropriate heading hierarchy (h2 for sections, h3 for subsections)

**Report Structure** (use this exact structure):

<section class="executive-summary">
    <h2>Executive Summary</h2>
    [Provide clear overview in paragraphs]
</section>

<section class="license-analysis">
    <h2>License Analysis</h2>
    <h3>License Distribution</h3>
    [Create HTML table with proper structure]
    
    <h3>License Categories</h3>
    [Categorize licenses]
    
    <h3>License Compliance Concerns</h3>
    [List concerns]
</section>

<section class="package-inventory">
    <h2>Package Inventory</h2>
    <h3>Package Summary</h3>
    [Statistics]
    
    <h3>Detailed Package List</h3>
    [HTML table with Package Name, Version, License, Source]
</section>

<section class="risk-assessment">
    <h2>Risk Assessment</h2>
    <div class="risk-high">
        <h3>High Priority Issues</h3>
        [List items]
    </div>
    
    <div class="risk-medium">
        <h3>Medium Priority Issues</h3>
        [List items]
    </div>
    
    <div class="risk-low">
        <h3>Low Priority Issues</h3>
        [List items]
    </div>
</section>

<section class="recommendations">
    <h2>Recommendations</h2>
    <h3>Immediate Actions Required</h3>
    <ol>[Numbered list]</ol>
    
    <h3>Best Practices</h3>
    <ul>[Bullet list]</ul>
    
    <h3>Long-term Considerations</h3>
    [Strategic recommendations]
</section>

<section class="summary-conclusion">
    <h2>Summary</h2>
    <div class="summary-box">
        <p><strong>Overall Project Status:</strong> [READY TO PROCEED / NEEDS ATTENTION / BLOCKED]</p>
        <p><strong>Key Findings:</strong> [2-3 sentences]</p>
        <p><strong>Compliance Posture:</strong> [Assessment]</p>
        <p><strong>Go/No-Go Recommendation:</strong> [Clear verdict]</p>
    </div>
</section>

<section class="appendix">
    <h2>Appendix</h2>
    <h3>Package Details</h3>
    [Additional technical information in tables or lists]
</section>

**Package Information**:
"""
            for pkg in key_info['packages'][:10]:
                prompt += f"\n- {pkg.get('id', 'Unknown')}"
                prompt += f"\n  License: {pkg.get('declared_licenses', ['Unknown'])}"
                prompt += f"\n  Homepage: {pkg.get('homepage_url', 'N/A')}"
                
        else:  # ERROR case
            prompt += """
**Your Task**: Generate an error analysis report in CLEAN HTML FORMAT (content only, NO <html>, <head>, or <body> tags).

CRITICAL FORMATTING RULES:
- Return ONLY the content HTML (divs, headings, paragraphs, tables, lists)
- Do NOT include <html>, <head>, <body>, <!DOCTYPE>, or <style> tags
- Use semantic HTML5 elements
- Use class names: 'error-section', 'error-critical', 'error-warning', 'code-block', 'troubleshooting-steps'

**Report Structure**:

<section class="error-summary">
    <h2>Error Summary</h2>
    [Overview]
</section>

<section class="root-cause">
    <h2>Root Cause Analysis</h2>
    <h3>Primary Error</h3>
    [Explanation]
    
    <h3>Contributing Factors</h3>
    [List factors]
</section>

<section class="error-details">
    <h2>Detailed Error Information</h2>
    <h3>Error Messages</h3>
    <pre><code>[Error messages]</code></pre>
    
    <h3>Affected Components</h3>
    [List components]
</section>

<section class="impact-assessment">
    <h2>Impact Assessment</h2>
    <h3>Compliance Risks</h3>
    [Explain risks]
    
    <h3>Missing Data</h3>
    [What's unavailable]
</section>

<section class="troubleshooting">
    <h2>Troubleshooting Guide</h2>
    <h3>Immediate Fixes</h3>
    <ol>[Step-by-step]</ol>
    
    <h3>Configuration Changes</h3>
    [Recommendations]
    
    <h3>Alternative Approaches</h3>
    [Backup strategies]
</section>

<section class="resolution">
    <h2>Resolution Steps</h2>
    <h3>Prerequisites</h3>
    [Requirements]
    
    <h3>Step-by-Step Resolution</h3>
    <ol>[Detailed steps]</ol>
    
    <h3>Verification</h3>
    [How to verify]
</section>

<section class="next-steps">
    <h2>Next Steps</h2>
    <h3>Immediate Actions</h3>
    <ul>[Prioritized list]</ul>
    
    <h3>Follow-up Tasks</h3>
    <ul>[Additional items]</ul>
    
    <h3>Escalation Criteria</h3>
    [When to escalate]
</section>

**Error Details**:
"""
            for project_id, issues in key_info['issues'].items():
                prompt += f"\n\nProject: {project_id}"
                for issue in issues:
                    prompt += f"\n- Severity: {issue.get('severity', 'Unknown')}"
                    prompt += f"\n- Source: {issue.get('source', 'Unknown')}"
                    prompt += f"\n- Message: {issue.get('message', 'Unknown')[:500]}..."
        
        prompt += "\n\nREMEMBER: Return ONLY content HTML without <html>, <head>, <body>, or <style> tags. Use proper semantic HTML5 with class names for styling."
        return prompt
    
    def create_html_template(self, content: str, key_info: Dict[str, Any], status: str) -> str:
        """Wrap the generated content in a complete HTML template."""
        status_color = {
            'SUCCESS': '#10b981',
            'ERROR': '#ef4444',
            'INCOMPLETE': '#f59e0b'
        }.get(status, '#6b7280')
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ORT Analysis Curation Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #1f2937;
            background: #f9fafb;
            padding: 20px;
        }}
        body {{
			font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
			background: 
				linear-gradient(135deg, rgba(102,126,234,0.8), rgba(118,75,162,0.8)),
				url('background.jpg') no-repeat center center fixed;
			background-size: cover;
			min-height: 100vh;
			display: flex;
			align-items: center;
			justify-content: center;
			padding: 125px 20px 20px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 20px;
            font-weight: 700;
        }}
        
        .metadata {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }}
        
        .metadata-item {{
            background: rgba(255,255,255,0.1);
            padding: 15px;
            border-radius: 6px;
        }}
        
        .metadata-item label {{
            display: block;
            font-size: 0.85em;
            opacity: 0.9;
            margin-bottom: 5px;
        }}
        
        .metadata-item .value {{
            font-size: 1.1em;
            font-weight: 600;
        }}
        
        .status-badge {{
            display: inline-block;
            padding: 6px 16px;
            border-radius: 20px;
            font-weight: 600;
            font-size: 0.9em;
            background: {status_color};
        }}
        
        .content {{
            padding: 40px;
        }}
        
        section {{
            margin-bottom: 40px;
        }}
        
        h2 {{
            color: #111827;
            font-size: 1.875em;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 3px solid #667eea;
        }}
        
        h3 {{
            color: #374151;
            font-size: 1.5em;
            margin-top: 25px;
            margin-bottom: 15px;
        }}
        
        p {{
            margin-bottom: 15px;
            color: #4b5563;
        }}
        
        .data-table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        
        .data-table thead {{
            background: #f3f4f6;
        }}
        
        .data-table th {{
            padding: 12px;
            text-align: left;
            font-weight: 600;
            color: #111827;
            border-bottom: 2px solid #e5e7eb;
        }}
        
        .data-table td {{
            padding: 12px;
            border-bottom: 1px solid #e5e7eb;
        }}
        
        .data-table tbody tr:hover {{
            background: #f9fafb;
        }}
        
        .risk-high {{
            border-left: 4px solid #ef4444;
            padding-left: 20px;
            margin: 20px 0;
        }}
        
        .risk-medium {{
            border-left: 4px solid #f59e0b;
            padding-left: 20px;
            margin: 20px 0;
        }}
        
        .risk-low {{
            border-left: 4px solid #10b981;
            padding-left: 20px;
            margin: 20px 0;
        }}
        
        .summary-box {{
            background: #f0f9ff;
            border: 2px solid #3b82f6;
            border-radius: 8px;
            padding: 25px;
            margin: 20px 0;
        }}
        
        .summary-box p {{
            margin-bottom: 12px;
        }}
        
        ul, ol {{
            margin-left: 25px;
            margin-bottom: 15px;
        }}
        
        li {{
            margin-bottom: 8px;
            color: #4b5563;
        }}
        
        code {{
            background: #f3f4f6;
            padding: 2px 6px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            color: #dc2626;
        }}
        
        pre {{
            background: #1f2937;
            color: #f9fafb;
            padding: 20px;
            border-radius: 6px;
            overflow-x: auto;
            margin: 20px 0;
        }}
        
        pre code {{
            background: none;
            color: inherit;
            padding: 0;
        }}
        
        .footer {{
            background: #f3f4f6;
            padding: 20px 40px;
            text-align: center;
            color: #6b7280;
            font-size: 0.9em;
        }}
        
        @media print {{
            body {{
                background: white;
                padding: 0;
            }}
            
            .container {{
                box-shadow: none;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>ORT Analysis Curation Report</h1>
            <h4>Generated by LTTS ORT Curation Report Generator</h4>
            <div class="metadata">
                <div class="metadata-item">
                    <label>Generated</label>
                    <div class="value">{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
                </div>
                <div class="metadata-item">
                    <label>Status</label>
                    <div class="value"><span class="status-badge">{status}</span></div>
                </div>
                <div class="metadata-item">
                    <label>Repository</label>
                    <div class="value" style="font-size: 0.9em; word-break: break-all;">{key_info['repository_url']}</div>
                </div>
                <div class="metadata-item">
                    <label>Revision</label>
                    <div class="value">{key_info['revision'][:12]}...</div>
                </div>
            </div>
        </div>
        
        <div class="content">
            {content}
        </div>
        
        <div class="footer">
            Generated by ORT Curation Report Generator | {datetime.now().strftime('%Y')}
        </div>
    </div>
</body>
</html>"""
        return html
    
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
                {"role": "system", "content": "You are an expert software compliance analyst specializing in open-source license compliance and dependency analysis. You generate clean HTML content (without html/head/body tags) with proper semantic structure and class names for styling."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,
            max_tokens=4000
        )
        
        content = response.choices[0].message.content
        
        # Wrap in complete HTML template
        report = self.create_html_template(content, key_info, status)
        
        return report
    
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
    output_file = f"curation-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.html"
    
    try:
        report = generator.generate_report(input_file)
        generator.save_report(report, output_file)
        print(f"\n✓ Successfully generated HTML report: {output_file}")
        print(f"✓ Open the file in your browser to view the report")
    except Exception as e:
        print(f"Error generating report: {str(e)}")
        exit(1)