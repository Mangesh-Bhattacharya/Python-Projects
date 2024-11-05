import scrapy
from scrapy.crawler import CrawlerProcess
from scrapy.utils.project import get_project_settings
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.edge.service import Service as EdgeService
from selenium.webdriver.chrome.options import Options as ChromeOptions
from selenium.webdriver.firefox.options import Options as FirefoxOptions
from selenium.webdriver.edge.options import Options as EdgeOptions
from webdriver_manager.chrome import ChromeDriverManager
from webdriver_manager.firefox import GeckoDriverManager
from webdriver_manager.microsoft import EdgeChromiumDriverManager
import pandas as pd
import sys
import random
import logging
import os

# Set up logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

# User-agent list for rotation
USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gecko/20100101 Firefox/89.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0 Safari/537.36'
]


class CombinedSpider(scrapy.Spider):
    name = 'combined_spider'

    def __init__(self, browser='chrome', *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.data = []  # Initialize an empty list to store scraped data

        try:
            # Select browser based on input
            if browser == 'chrome':
                options = ChromeOptions()
                options.add_argument("--headless")
                options.add_argument("--disable-gpu")
                # Update path if necessary
                options.binary_location = "C:/Program Files/Google/Chrome/Application/chrome.exe"
                self.driver = webdriver.Chrome(service=ChromeService(
                    ChromeDriverManager().install()), options=options)

            elif browser == 'firefox':
                options = FirefoxOptions()
                options.add_argument("--headless")
                # Update path if necessary
                options.binary_location = "C:/Program Files/Mozilla Firefox/firefox.exe"
                self.driver = webdriver.Firefox(service=FirefoxService(
                    GeckoDriverManager().install()), options=options)

            elif browser == 'edge':
                options = EdgeOptions()
                options.add_argument("--headless")
                self.driver = webdriver.Edge(service=EdgeService(
                    EdgeChromiumDriverManager().install()), options=options)

            else:
                logging.error(
                    f"Unsupported browser: {browser}. Please choose 'chrome', 'firefox', or 'edge'.")
                sys.exit(1)

        except Exception as e:
            logging.error(f"Failed to initialize the {browser} driver: {e}")
            sys.exit(1)

    def start_requests(self):
        urls = [
            'https://example.com',  # Add other URLs as needed
        ]
        for url in urls:
            headers = {'User-Agent': random.choice(USER_AGENTS)}
            yield scrapy.Request(url=url, headers=headers, callback=self.parse, errback=self.handle_error)

    def parse(self, response):
        try:
            self.driver.get(response.url)
            page_title = self.driver.title
            logging.info(f'Title of the page: {page_title}')

            # Add scraped data to the list
            self.data.append({
                'URL': response.url,
                'Title': page_title,
            })

            # Save data to CSV and Excel incrementally in a table-like format
            df = pd.DataFrame(self.data)
            df.to_csv('scraped_data.csv', index=False)
            with pd.ExcelWriter('scraped_data.xlsx', engine='xlsxwriter') as writer:
                df.to_excel(writer, sheet_name='Scraped Data', index=False)
                workbook = writer.book
                worksheet = writer.sheets['Scraped Data']

                # Set column width for better readability in Excel
                for idx, col in enumerate(df.columns):
                    max_len = df[col].astype(str).map(len).max()
                    worksheet.set_column(idx, idx, max_len + 2)

            logging.info(
                "Data saved to scraped_data.csv and scraped_data.xlsx")

        except Exception as e:
            logging.error(f"Error parsing page {response.url}: {e}")

    def handle_error(self, failure):
        logging.error(f"Request failed: {failure.request.url}")

    def close(self, reason):
        # Quit the driver when the spider finishes or fails
        if self.driver:
            self.driver.quit()
        logging.info("Web scraper finished.")


if __name__ == "__main__":
    print("Starting the web scraper...")

    # Prompt user for browser choice
    browser_choice = input(
        "Enter the browser you want to use ('chrome', 'firefox', 'edge'): ").strip().lower()

    # Start Scrapy crawler
    process = CrawlerProcess(get_project_settings())
    process.crawl(CombinedSpider, browser=browser_choice)
    process.start()

    print("Web scraper finished.")
