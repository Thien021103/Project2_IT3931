import re

def is_about_topic(text, keywords):
    # Function to create a regex pattern for a keyword with variations
    def create_pattern(keyword):
        keyword = keyword.lower()
        # Replace specific characters with regex groups to handle accented and unaccented versions
        keyword = keyword.replace('t', '[tT]')
        keyword = re.sub(r'[ấa]', '[ấaA]', keyword)
        keyword = keyword.replace('n', '[nN]')
        keyword = keyword.replace('c', '[cC]')
        keyword = re.sub(r'[ôo]', '[ôoO]', keyword)
        keyword = keyword.replace('g', '[gG]')
        # Allow spaces or no spaces between characters
        return r'\s*'.join(list(keyword))
    
    # Create regex patterns for each keyword
    patterns = [create_pattern(keyword) for keyword in keywords]
    
    # Combine patterns with OR operator
    combined_pattern = '|'.join(patterns)
    
    # Compile the combined regex pattern
    regex = re.compile(combined_pattern, re.IGNORECASE)
    
    # Search for the pattern in the text
    return bool(regex.search(text))

# Example usage
text = " t a n c o n g "
keywords = ['tấn công', 'tan cong', 'tancong', 'tan  cong', 't a ncong']

if is_about_topic(text, keywords):
    print("The text is about the topic.")
else:
    print("The text is not about the topic.")

