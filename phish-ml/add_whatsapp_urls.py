#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Add legitimate WhatsApp URLs to the training dataset
"""

import pandas as pd
import os

def add_whatsapp_urls():
    """Add legitimate WhatsApp URLs to the dataset"""
    
    # Legitimate WhatsApp URLs
    whatsapp_urls = [
        'https://web.whatsapp.com',
        'https://whatsapp.com',
        'https://api.whatsapp.com',
        'https://whatsapp.net',
        'https://web.whatsapp.com/',
        'https://whatsapp.com/',
        'https://web.whatsapp.com/download',
        'https://whatsapp.com/download',
        'https://web.whatsapp.com/desktop',
        'https://whatsapp.com/desktop',
        'https://web.whatsapp.com/features',
        'https://whatsapp.com/features',
        'https://web.whatsapp.com/security',
        'https://whatsapp.com/security',
        'https://web.whatsapp.com/privacy',
        'https://whatsapp.com/privacy',
        'https://web.whatsapp.com/terms',
        'https://whatsapp.com/terms',
        'https://web.whatsapp.com/help',
        'https://whatsapp.com/help',
        'https://web.whatsapp.com/business',
        'https://whatsapp.com/business',
        'https://web.whatsapp.com/status',
        'https://whatsapp.com/status',
        'https://web.whatsapp.com/contact',
        'https://whatsapp.com/contact',
        'https://web.whatsapp.com/about',
        'https://whatsapp.com/about',
        'https://web.whatsapp.com/careers',
        'https://whatsapp.com/careers'
    ]
    
    # Create DataFrame with legitimate WhatsApp URLs
    whatsapp_df = pd.DataFrame({
        'url': whatsapp_urls,
        'label': [0] * len(whatsapp_urls)  # 0 = legitimate
    })
    
    print(f"✅ Created {len(whatsapp_urls)} legitimate WhatsApp URLs")
    
    # Load existing comprehensive dataset
    if os.path.exists('data/comprehensive_urls.csv'):
        existing_df = pd.read_csv('data/comprehensive_urls.csv')
        print(f"📥 Loaded existing dataset: {len(existing_df)} URLs")
        
        # Combine datasets
        combined_df = pd.concat([existing_df, whatsapp_df], ignore_index=True)
        
        # Remove any duplicates
        combined_df = combined_df.drop_duplicates(subset=['url'], keep='first')
        
        print(f"📊 Combined dataset: {len(combined_df)} URLs")
        print(f"   Legitimate: {len(combined_df[combined_df['label'] == 0])}")
        print(f"   Phishing: {len(combined_df[combined_df['label'] == 1])}")
        
        # Save updated dataset
        combined_df.to_csv('data/comprehensive_urls.csv', index=False)
        print(f"💾 Saved updated dataset to: data/comprehensive_urls.csv")
        
        return combined_df
    else:
        print("❌ Comprehensive dataset not found!")
        return None

def main():
    """Main function"""
    try:
        print("🔄 Adding legitimate WhatsApp URLs to dataset...")
        df = add_whatsapp_urls()
        
        if df is not None:
            print(f"\n✅ Successfully added WhatsApp URLs!")
            print(f"   Total URLs: {len(df)}")
            print(f"   Ready for retraining!")
        else:
            print("❌ Failed to add WhatsApp URLs")
            
    except Exception as e:
        print(f"❌ Error: {e}")

if __name__ == "__main__":
    main()
