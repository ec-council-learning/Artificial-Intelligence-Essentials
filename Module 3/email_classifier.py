import pandas as pd
import numpy as np
import re
import os
from datetime import datetime
import unicodedata
import email.utils

# Column mapping
COLUMN_MAPPING = {
    'sender': 'sender',
    'receiver': 'recipient',
    'date': 'datetime',
    'subject': 'subject',
    'body': 'body',
    'urls': 'urls',
    'label': 'label'
}

# Output column order
OUTPUT_COLUMNS = [
    'sender_name',
    'sender_email',
    'sender_domain',
    'recipient_name',
    'recipient_email',
    'datetime',
    'subject',
    'body',
    'urls',
    'label'
]

def clean_text(text):
    """Clean text by removing invalid characters and normalizing unicode"""
    if pd.isna(text) or text == 'NULL':
        return 'NULL'
    
    try:
        # Convert to string
        text = str(text)
        
        # Normalize unicode characters
        text = unicodedata.normalize('NFKD', text)
        
        # Remove non-ASCII characters
        text = text.encode('ascii', 'ignore').decode('ascii')
        
        # Remove control characters
        text = ''.join(char for char in text if ord(char) >= 32)
        
        # Remove extra whitespace
        text = ' '.join(text.split())
        
        # Check if the cleaned text is empty or contains only special characters
        cleaned = text.strip()
        if not cleaned or not any(c.isalnum() for c in cleaned):
            return 'NULL'
        
        return cleaned
    except:
        return 'NULL'

def extract_domain(email):
    """Extract domain from email address"""
    if email == 'NULL' or pd.isna(email):
        return 'NULL'
    
    try:
        parts = email.split('@')
        if len(parts) != 2:
            return 'NULL'
        return parts[1]
    except:
        return 'NULL'

def is_junk_text(text):
    """Check if a string contains meaningless junk data"""
    if text == 'NULL':
        return False
    
    # Junk patterns to check for
    junk_patterns = [
        r'A{2,}f?A+',                     # Multiple As with possible 'f'
        r'A+""A+f?A+',                    # Pattern with double quotes
        r'A+\?s?A+\?z?A+f?A+',            # Pattern with question marks
        r'Â+',                            # Non-ASCII character pattern
        r'^[^a-zA-Z0-9]*$',               # Only special characters
        r'[A-Z]{2,}f[A-Z]{2,}',           # Capital letters with 'f'
        r'fA\'?A',                        # Patterns seen in examples
        r'\?T[Aa]f',                      # More patterns from examples
        r'[A-Z][A-Z]\"\"[A-Z]{2,}f'       # Pattern from examples
    ]
    
    # Check if the text matches any junk pattern
    for pattern in junk_patterns:
        if re.search(pattern, text):
            return True
    
    # Check for repeated characters that might be encoding errors
    if len(set(text)) < len(text) / 3 and len(text) > 5:
        return True
    
    # Check for specific junk strings
    junk_strings = ["AAAfAAAAA", "AAAAfA?s", "AAAfA'A", "?TAfA"]
    for junk in junk_strings:
        if junk in text:
            return True
            
    return False

class EmailDataProcessor:
    def __init__(self):
        self.issues = []
        self.corrections = []
        self.df = None
        self.stats = {
            'total_rows': 0,
            'cleaned_rows': 0,
            'removed_rows': 0,
            'null_counts': {}
        }

    def load_file(self):
        """Load and clean the input file"""
        while True:
            print("\nPlease enter the full path to your input file (.csv or .xlsx):")
            file_path = input().strip('"').strip("'")
            
            if not os.path.exists(file_path):
                print("File not found. Please try again.")
                continue
            
            try:
                if file_path.endswith('.csv'):
                    encodings = ['utf-8', 'latin1', 'iso-8859-1', 'cp1252']
                    for encoding in encodings:
                        try:
                            self.df = pd.read_csv(file_path, encoding=encoding, on_bad_lines='skip')
                            break
                        except Exception:
                            continue
                else:
                    self.df = pd.read_excel(file_path)
                
                if self.df is None:
                    raise Exception("Unable to read file with any supported encoding")
                
                # Clean column names and remove unnamed columns
                self.df.columns = self.df.columns.str.strip().str.lower()
                self.df = self.df.loc[:, ~self.df.columns.str.contains('^Unnamed')]
                
                # Clean all text columns
                for col in self.df.columns:
                    if self.df[col].dtype == 'object':
                        self.df[col] = self.df[col].apply(clean_text)
                
                # Fill NaN values with NULL
                self.df = self.df.fillna('NULL')
                
                # Rename columns
                self.df = self.df.rename(columns=COLUMN_MAPPING)
                
                # Update statistics
                self.stats['total_rows'] = len(self.df)
                
                return file_path
            except Exception as e:
                print(f"Error loading file: {str(e)}")
                print("Would you like to try again? (yes/no):")
                if input().lower() not in ['yes', 'y']:
                    return None
                continue

    def extract_email_components(self, email_string, is_sender=True):
        """Extract and validate email components"""
        if pd.isna(email_string) or email_string == 'NULL':
            return 'NULL', 'NULL'
        
        try:
            email_string = clean_text(email_string)
            if email_string == 'NULL':
                return 'NULL', 'NULL'
            
            # Remove any < > brackets
            email_string = email_string.replace('<', ' ').replace('>', ' ')
            
            # Try to find email address
            email_pattern = r'[\w\.-]+@[\w\.-]+\.\w+'
            email_match = re.search(email_pattern, email_string)
            
            if email_match:
                email = email_match.group(0)
                # Get name by removing email and cleaning
                name = clean_text(email_string.replace(email, ''))
                if not name or name == 'NULL':
                    name = email.split('@')[0]
                return name, email
            
            return 'NULL', 'NULL'
        except:
            return 'NULL', 'NULL'

    def parse_email_date(self, date_string):
        """Parse and standardize date format"""
        if pd.isna(date_string) or date_string == 'NULL':
            return 'NULL'
        
        try:
            date_string = clean_text(date_string)
            if date_string == 'NULL':
                return 'NULL'
            
            # Skip if it contains obvious non-date content
            if len(date_string) < 8 or not any(char.isdigit() for char in date_string):
                return 'NULL'
            
            # Try email.utils parser first
            try:
                dt = email.utils.parsedate_to_datetime(date_string)
                return dt.strftime('%a, %d %b %Y %H:%M:%S')
            except:
                pass
            
            # Try dateutil parser as fallback
            try:
                from dateutil import parser
                dt = parser.parse(date_string)
                return dt.strftime('%a, %d %b %Y %H:%M:%S')
            except:
                return 'NULL'
        except:
            return 'NULL'

    def is_junk_row(self, row):
        """Determine if a row is junk and should be removed"""
        # Count NULL values in the row
        null_count = sum(1 for value in row if value == 'NULL')
        
        # If most fields are NULL, check if any non-NULL fields contain junk
        if null_count >= len(row) - 2:
            # Check if any non-NULL values are junk
            for value in row:
                if value != 'NULL' and is_junk_text(value):
                    return True
        
        # Keep rows with valid email addresses regardless of other fields
        if 'sender_email' in row.index and row['sender_email'] != 'NULL':
            if '@' in row['sender_email']:
                return False
        
        # If sender and recipient emails are both NULL and there are many NULL fields, consider junk
        if ('sender_email' in row.index and row['sender_email'] == 'NULL' and
            'recipient_email' in row.index and row['recipient_email'] == 'NULL' and
            null_count >= len(row) - 2):
            return True
        
        # Check for specific junk strings in any field
        for value in row:
            if isinstance(value, str) and any(junk in value for junk in ["AAAfAAAAA", "AAAAfA?s", "AAAfA'A", "?TAfA"]):
                return True
            
        return False

    def process_data(self):
        """Process and clean the data"""
        if self.df is None:
            print("No data loaded")
            return None
        
        processed_df = self.df.copy()
        
        # Process sender/recipient information
        for field in ['sender', 'recipient']:
            if field in processed_df.columns:
                names = []
                emails = []
                for value in processed_df[field]:
                    name, email = self.extract_email_components(value, field == 'sender')
                    names.append(name)
                    emails.append(email)
                processed_df[f'{field}_name'] = names
                processed_df[f'{field}_email'] = emails
                # Remove original column
                processed_df = processed_df.drop(field, axis=1)
        
        # Process dates
        if 'datetime' in processed_df.columns:
            processed_df['datetime'] = processed_df['datetime'].apply(self.parse_email_date)
        
        # Clean text fields
        text_columns = ['subject', 'body', 'urls', 'label']
        for col in text_columns:
            if col in processed_df.columns:
                processed_df[col] = processed_df[col].apply(clean_text)
        
        # Truncate body text
        if 'body' in processed_df.columns:
            processed_df['body'] = processed_df['body'].apply(
                lambda x: x[:1000] if x != 'NULL' else 'NULL'
            )
        
        # Extract domain from sender email
        if 'sender_email' in processed_df.columns:
            processed_df['sender_domain'] = processed_df['sender_email'].apply(extract_domain)
        
        # Remove junk rows
        initial_count = len(processed_df)
        processed_df = processed_df[~processed_df.apply(self.is_junk_row, axis=1)]
        
        # Enhanced junk removal - check for specific patterns
        to_drop = []
        for idx, row in processed_df.iterrows():
            for col in row.index:
                val = str(row[col])
                if any(pattern in val for pattern in ["AAAfAAAAA", "AAAAfA?sA", "AAAfA'A?A?TAfA"]):
                    to_drop.append(idx)
                    break
        
        processed_df = processed_df.drop(to_drop)
        removed_count = initial_count - len(processed_df)
        
        # Rearrange columns to match required order
        final_columns = [col for col in OUTPUT_COLUMNS if col in processed_df.columns]
        processed_df = processed_df[final_columns]
        
        # Update statistics
        self.stats['cleaned_rows'] = len(processed_df)
        self.stats['removed_rows'] = removed_count
        for col in processed_df.columns:
            self.stats['null_counts'][col] = (processed_df[col] == 'NULL').sum()
        
        return processed_df

    def generate_report(self, processed_df):
        """Generate a detailed processing report"""
        report = []
        report.append("=== Email Data Processing Report ===")
        
        report.append("\nProcessing Statistics:")
        report.append(f"Total rows initially loaded: {self.stats['total_rows']}")
        report.append(f"Rows removed as junk: {self.stats['removed_rows']}")
        report.append(f"Rows in final clean dataset: {self.stats['cleaned_rows']}")
        
        report.append("\nNULL Value Statistics:")
        for col, count in self.stats['null_counts'].items():
            if self.stats['cleaned_rows'] > 0:
                percentage = (count / self.stats['cleaned_rows']) * 100
                report.append(f"{col}: {count} NULL values ({percentage:.1f}%)")
        
        report.append("\nOutput Columns:")
        for col in processed_df.columns:
            report.append(f"- {col}")
        
        report.append("\nSample of Processed Data:")
        report.append("First 5 rows of cleaned data:")
        report.append(str(processed_df.head()))
        
        return "\n".join(report)

    def save_report(self, report, output_path):
        """Save the processing report"""
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(report)

def main():
    print("Email Data Processor")
    print("===================")
    
    processor = EmailDataProcessor()
    
    # Load file
    file_path = processor.load_file()
    if not file_path:
        print("No file provided or unable to load file. Exiting...")
        return
    
    # Process data
    processed_df = processor.process_data()
    if processed_df is None:
        print("Data processing failed.")
        return
    
    # Generate and display report
    report = processor.generate_report(processed_df)
    print("\n" + report)
    
    # Ask for confirmation
    while True:
        print("\nDo you want to save the processed data and report? (yes/no):")
        response = input().lower()
        if response in ['yes', 'y', 'no', 'n']:
            break
        print("Please answer 'yes' or 'no'")

    if response in ['yes', 'y']:
        # Create output filenames
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        base_path = os.path.splitext(file_path)[0]
        
        output_path = f"{base_path}_processed_{timestamp}.csv"
        processed_df.to_csv(output_path, index=False, encoding='utf-8')
        
        report_path = f"{base_path}_report_{timestamp}.txt"
        processor.save_report(report, report_path)
        
        print(f"\nProcessed file saved to: {output_path}")
        print(f"Report saved to: {report_path}")
    else:
        print("\nOperation cancelled by user")

if __name__ == "__main__":
    main()
    
##This program is awesome