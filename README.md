
<h1>Phishing Detection System — Using Trie, Graph & Priority Queue</h1>

<h2>Overview</h2>
<p>
This project detects phishing attacks by analyzing email addresses, email content, and suspicious URLs.
It uses efficient data structures such as <b>Trie</b>, <b>Graph</b>, and <b>Max-Heap Priority Queue</b>
to identify malicious patterns. The system categorizes threats and generates a final threat report
grouped by attack type and severity.
</p>

<h2> Key Features</h2>
<ul>
    <li>Detects malicious emails using Trie</li>
    <li>Finds phishing keywords in messages</li>
    <li>Identifies suspicious URLs using Graph traversal</li>
    <li>Categorizes threats: Phishing, Spear Phishing, Malware, Vishing</li>
    <li>Prioritizes threats using Max-Heap</li>
    <li>Generates a structured Threat Report</li>
</ul>

<h2> How It Works</h2>
<ol>
    <li>Load suspicious email patterns into Trie</li>
    <li>Load phishing keywords into Trie</li>
    <li>Scan emails and content</li>
    <li>Build Graph of URL links</li>
    <li>Detect URLs in phishing blacklist</li>
    <li>Categorize threats by pattern</li>
    <li>Assign priority using Max-Heap</li>
    <li>Generate final Threat Report</li>
</ol>

<h2> Run Instructions</h2>
<pre>
python Code.py
</pre>

<h2>Time Complexity Summary</h2>
<table border="1" cellpadding="6">
    <tr><th>Component</th><th>Time Complexity</th></tr>
    <tr><td>Trie Insert/Search</td><td>O(M)</td></tr>
    <tr><td>Graph Add Node/Edge</td><td>O(1)</td></tr>
    <tr><td>Graph Analysis</td><td>O(V+E)</td></tr>
    <tr><td>Categorization</td><td>O(N)</td></tr>
    <tr><td>Priority Queue Ops</td><td>O(log N)</td></tr>
    <tr><td>Report Generation</td><td>O(N)</td></tr>
</table>

<h2>Example Output</h2>
<pre>
Threat Report Generated:
Category: Phishing Email
    Email: info@maliciousattachment.com       URL: http://fakeoffer.com       Severity: Medium

Category: Spear Phishing
    Email: notification@yourservice.com       URL: http://yourbank.com       Severity: High
</pre>



</body>
</html>
