"""
Preamble:
This project is designed to detect potential phishing threats by analyzing emails, URLs, and content. 
It employs Trie and Graph data structures to filter suspicious keywords and phishing URLs and 
categorizes the threats based on their characteristics. It then prioritizes these threats using 
a priority queue and generates a report for threat analysis.

Classes:
1. ThreatReport - Manages threat data and generates/display reports.
2. Detect - Contains sub-classes Trie (for keyword search) and Graph (for URL analysis).
3. Categorize - Categorizes phishing threats based on keywords and other characteristics.
4. PriorityQueue - Implements a max-heap to prioritize threats.
5. ThreatPrioritizer - Adds threats to a priority queue for prioritized retrieval.

Time Complexities:
- ThreatReport class methods: O(1) for adding, O(N) for report generation/display.
- Trie methods (insert_d, search_d, keyword): O(M) where M is length of the word.
- Graph methods (add_url, add_link, is_phishing, analyze_urls): O(1) for add/link, O(V+E) for analysis.
- Categorize.categorize_phishing: O(N) for N entries.
- PriorityQueue methods: O(log N) for add/delete.
"""


class ThreatReport:
    def __init__(self):
        # Initializes an empty dictionary to store threat data by category.
        self.report_data = {}

    def add_threat(self, category, email, url, severity):
        # Adds a threat under the specified category with email, url, and severity details.
        # Time Complexity: O(1)
        if category not in self.report_data:
            self.report_data[category] = []
        self.report_data[category].append({
            "email": email,
            "url": url,
            "severity": severity
        })

    def generate_report(self):
        # Returns the entire threat data dictionary.
        # Time Complexity: O(1)
        return self.report_data

    def display_report(self):
        # Prints the threat data, categorized and formatted.
        # Time Complexity: O(N) where N is the number of threats
        for category, threats in self.report_data.items():
            print("Category: " + category)
            for threat in threats:
                print("    Email: " + threat['email'] + "       URL: " + threat['url'] + "       Severity: " + threat['severity'])
            print()


class Detect:
    class NodeD:
        # Helper class for Trie, each node holds a dictionary of children and word end indicator.
        def __init__(self):
            self.dict = {}
            self.word_end = False

    class Trie:
        # Trie data structure to store and search keywords and emails efficiently.
        def __init__(self):
            self.root = Detect.NodeD()

        def insert_d(self, word):
            # Inserts a word into the Trie.
            # Time Complexity: O(M), where M is the length of the word
            node = self.root
            for ch in word:
                if ch not in node.dict:
                    node.dict[ch] = Detect.NodeD()
                node = node.dict[ch]
            node.word_end = True

        def search_d(self, word):
            # Searches for a word in the Trie and returns True if it exists.
            # Time Complexity: O(M), where M is the length of the word
            node = self.root
            for ch in word:
                if ch not in node.dict:
                    return False
                node = node.dict[ch]
            return node.word_end

        def keyword(self, word):
            # Wrapper for search_d method, checks for keyword existence.
            # Time Complexity: O(M)
            return self.search_d(word)

    class Graph:
        # Graph class for managing URLs and links, with phishing blacklist.
        def __init__(self):
            self.adjacency_list = {}
            self.phishing_blacklist = {
                "http://phishingsite.com", 
                "http://fakebank.com", 
                "http://examplesite.com", 
                "http://fakeoffer.com", 
                "http://discountsite.com",
                "http://yourbank.com",
                "http://downloadmalware.com",
                "http://claimyourprize.com",
                "http://fakecollections.com"
            }

        def add_url(self, url):
            # Adds a URL as a node in the graph.
            # Time Complexity: O(1)
            if url not in self.adjacency_list:
                self.adjacency_list[url] = []

        def add_link(self, from_url, to_url):
            # Adds a directed edge from from_url to to_url.
            # Time Complexity: O(1)
            self.add_url(from_url)
            self.add_url(to_url)
            self.adjacency_list[from_url].append(to_url)

        def is_phishing(self, url):
            # Checks if a URL is in the phishing blacklist.
            # Time Complexity: O(1)
            return url in self.phishing_blacklist

        def analyze_urls(self):
            # Finds and returns all URLs in the phishing blacklist and their links.
            # Time Complexity: O(V+E), where V is the number of URLs and E is the number of links
            detected_urls = []
            suspicious_links = {}
            
            for url in self.adjacency_list:
                if self.is_phishing(url):
                    detected_urls.append(url)
                    suspicious_links[url] = self.adjacency_list[url]

            return detected_urls, suspicious_links

class Categorize:
    # Categorizes detected phishing threats based on keywords or characteristics.
    def __init__(self, data):
        self.data = data
        self.phishing_categories = {
            "Phishing Email": [],
            "Spear Phishing": [],
            "Vishing": [],
            "Malware Attachment": []
        }

    def categorize_phishing(self):
        # Categorizes each data entry based on keywords and threat characteristics.
        # Time Complexity: O(N), where N is the number of entries in data
        for entry in self.data:
            if 'suspicious_keyword' in entry:
                if entry['suspicious_keyword'] in ["free", "win", "offer"]:
                    self.phishing_categories["Phishing Email"].append(entry['email'])
                elif entry['suspicious_keyword'] in ["click", "verify"]:
                    self.phishing_categories["Spear Phishing"].append(entry['email'])
                elif entry['contains_ip']:
                    self.phishing_categories["Vishing"].append(entry['email'])
                else:
                    self.phishing_categories["Malware Attachment"].append(entry['email'])

class PriorityQueue:
    # Implements a max-heap priority queue for threat prioritization.
    def __init__(self):
        self.heap = []

    def isEmpty(self):
        # Checks if the queue is empty.
        # Time Complexity: O(1)
        return len(self.heap) == 0

    def size(self):
        # Returns the size of the heap.
        # Time Complexity: O(1)
        return len(self.heap)

    def parent(self, index):
        # Calculates the parent index in the heap.
        # Time Complexity: O(1)
        return (index - 1) // 2

    def add(self, key, value):
        # Adds a threat with priority key into the queue.
        # Time Complexity: O(log N), where N is the size of the heap
        tup = (key, value)
        self.heap.append(tup)
        self.heapify_up(len(self.heap) - 1)

    def heapify_up(self, index):
        # Heapifies up to maintain the max-heap property.
        # Time Complexity: O(log N)
        while index > 0:
            parent = self.parent(index)
            if self.heap[parent][0] < self.heap[index][0]:
                self.heap[index], self.heap[parent] = self.heap[parent], self.heap[index]
                index = parent
            else:
                break

    def heapify_down(self, index):
        # Heapifies down to maintain the max-heap property.
        # Time Complexity: O(log N)
        large = index
        left = 2 * index + 1
        right = 2 * index + 2
        if left < len(self.heap) and self.heap[left][0] > self.heap[large][0]:  
            large = left
        if right < len(self.heap) and self.heap[right][0] > self.heap[large][0]:  
            large = right
        if index != large:
            self.heap[large], self.heap[index] = self.heap[index], self.heap[large]
            self.heapify_down(large)

    def delete(self):
        # Deletes the highest priority threat.
        # Time Complexity: O(log N)
        if self.isEmpty():
            return "Empty priority queue"
        elif self.size() == 1:
            return self.heap.pop()
        else:
            maxval = self.heap[0]
            self.heap[0] = self.heap.pop()
            self.heapify_down(0)
            return maxval

class ThreatPrioritizer:
    # Adds threats to priority queue based on severity.
    def __init__(self):
        self.priority_queue = PriorityQueue()

    def add_threat(self, threat, priority):
        # Adds a threat with a specified priority to the queue.
        # Time Complexity: O(log N)
        self.priority_queue.add(priority, threat)  

    def get_prioritized_threats(self):
        # Retrieves threats in prioritized order.
        # Time Complexity: O(log N) for each retrieval
        threats = []
        while not self.priority_queue.isEmpty():
            threats.append(self.priority_queue.delete())
        return threats

if __name__ == "__main__":
    # Instantiate the Detect class to access Trie and Graph for keyword detection and URL analysis
    detect = Detect()
    
    # Initialize Tries for storing email addresses and keywords
    email_trie = detect.Trie()         # Trie for detecting suspicious email addresses
    keyword_trie = detect.Trie()       # Trie for detecting suspicious keywords in email content

    # List of suspicious emails to add to email_trie for phishing detection
    emails = [
        "alert@paypal-secure-login.com", 
        "notification@yourservice.com", 
        "support@youraccount-update.com", 
        "security@onlinebanking-alert.com", 
        "contact@discount-offer.com",
        "security@yourbank.com",
        'info@maliciousattachment.com'
    ]
    
    # Insert each suspicious email into email_trie
    for e in emails:
        email_trie.insert_d(e)
    
    # Define keywords associated with phishing to add to keyword_trie 
    keywords = [
        "free", "account", "prize", 
        "limited-time", "offer", "alert", 
        "discount", "click", "verify", 
        "verification", "winner", "pay", "payment" , "malware" , "suspended"
    ]
    
    # Insert each keyword into keyword_trie
    for key in keywords:
        keyword_trie.insert_d(key)

    # List of emails and email content to scan for suspicious patterns
    email_list = [
        "notification@yourservice.com", 
        "abc@gmail.com", 
        "support@youraccount-update.com", 
        "contact@discount-offer.com", 
        "def@gmail.com",
        "alert@paypal-secure-login.com",
        "security@yourbank.com",
        'info@maliciousattachment.com'
    ]
    
    # Corresponding email content to check for suspicious keywords
    email_content = [
        "Congratulations! You have won a free prize.", 
        "Hall ticket is available.", 
        "Your account will be suspended unless you verify it.", 
        "Claim your discount on the next purchase.",
        "Exciting coding challenges.",
        "Your PayPal account has an urgent security alert. Please log in to verify your account information.",
        "Important: Your bank account login attempt was blocked. Verify your identity to regain access.",
        "You have a new secure message. Download the attachment to view details."
    ]                     

    # Set to hold emails identified as suspicious
    detected_emails = set()
    
    # Check each email address in email_list using email_trie
    for email in email_list:
        if email_trie.search_d(email):
            detected_emails.add(email)

    # Check for suspicious keywords in each email content using keyword_trie
    for index, content in enumerate(email_content):
        words = content.lower().split()
        for word in words:
            word = ''.join(filter(str.isalnum, word))  # Clean up punctuation
            if keyword_trie.keyword(word):
                detected_emails.add(email_list[index])  # Flag email as suspicious
                break

    # Convert set of detected suspicious emails to a list
    detect_emails = list(detected_emails)

    # Create a Graph instance for URL connections and suspicious link detection
    url_graph = detect.Graph()

     # Add URLs and links between URLs for network analysis
    url_graph.add_link("http://example.com", "http://example.com/page1")
    url_graph.add_link("http://phishingsite.com", "http://phishingsite.com/fake-login")
    url_graph.add_link("http://fakeoffer.com", "http://fakeoffer.com/page1")
    url_graph.add_link("http://google.com", "http://google.com/page1")
    url_graph.add_link("http://discountsite.com", "http://discountsite.com/signup")
    url_graph.add_link("http://downloadmalware.com","http://downloadmalware.com/freesoftware")
    url_graph.add_link("http://claimyourprize.com","http://claimprize-winner.com")
    url_graph.add_link("http://fakecollections.com","http://fakecollections.com/special")
    url_graph.add_link("http://yourbank.com","http://yourbank.com/login")

    # Analyze URLs for any that match phishing patterns in the blacklist
    urls_detected, suspicious_links = url_graph.analyze_urls()

    # Sample data with email details for categorization
    data = [
        {'email':  detect_emails[4], 'suspicious_keyword': 'free', 'url_pattern': urls_detected[1], 'contains_ip': 0},
        {'email':  detect_emails[5], 'suspicious_keyword': 'verify', 'url_pattern': urls_detected[6], 'contains_ip': 0},
        {'email': detect_emails[0], 'suspicious_keyword': 'urgent', 'url_pattern': urls_detected[0], 'contains_ip': 1},  
        {'email': detect_emails[2], 'suspicious_keyword': 'attachment', 'url_pattern': urls_detected[3], 'contains_ip': 0}, 
        {'email': detect_emails[2], 'suspicious_keyword': 'claim', 'url_pattern': urls_detected[4], 'contains_ip': 0}, 
        {'email': detect_emails[0], 'suspicious_keyword': 'limited-time', 'url_pattern': urls_detected[5], 'contains_ip': 0},  
        {'email': detect_emails[1], 'suspicious_keyword': 'suspended', 'url_pattern': urls_detected[1], 'contains_ip': 1},
        {'email':  detect_emails[3], 'suspicious_keyword': 'malware', 'url_pattern': urls_detected[2], 'contains_ip': 0} 
    ]

    # Categorize phishing types based on data patterns
    phishing_data = Categorize(data)
    phishing_data.categorize_phishing()

    # Retrieve phishing categories for threat prioritization
    categories = list(phishing_data.phishing_categories.keys())

    # Instantiate ThreatPrioritizer for prioritizing phishing threats
    prioritizer = ThreatPrioritizer()
    
    # Priority dictionary maps categories to threat levels
    prio_dict = {"Vishing": [1,"Low"], "Phishing Email": [2,"Medium"], "Spear Phishing": [3,"High"], "Malware Attachment": [4,"Critical"]}

    # Add categorized threats to priority queue based on priority level
    for category in categories:
        for email in phishing_data.phishing_categories[category]:
            prioritizer.add_threat(email, prio_dict[category][0])

    # Retrieve threats in priority order
    prioritized_threats = prioritizer.get_prioritized_threats()

    # Initialize ThreatReport for generating and displaying phishing report
    threat_report = ThreatReport()
    
    # Add threat information to the report by category
    for entry in data:
        for category in categories:
            if entry['email'] in phishing_data.phishing_categories[category]:
                threat_report.add_threat(category, entry['email'], entry['url_pattern'], prio_dict[category][1])

    # Generate and display the final threat report
    report = threat_report.generate_report()
    print("Threat Report Generated:")
    threat_report.display_report()

    # Display other suspicious links found
    print("Other Suspicious Links:")
    for link in  suspicious_links.values():
        print(link)
