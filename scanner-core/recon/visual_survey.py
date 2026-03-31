import os
import time
import base64
from typing import List, Dict, Any
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
from selenium.common.exceptions import UnexpectedAlertPresentException, TimeoutException

class VisualSurveyor:
    """Captures screenshots of discovered URLs using a headless browser"""
    
    def __init__(self, output_dir: str = "public/screenshots", timeout: int = 10):
        self.output_dir = output_dir
        self.timeout = timeout
        
        # Ensure output directory exists
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir, exist_ok=True)
            
        self.options = Options()
        self.options.add_argument("--headless")
        self.options.add_argument("--no-sandbox")
        self.options.add_argument("--disable-dev-shm-usage")
        self.options.add_argument("--window-size=1280,720")
        
    def capture_screenshot(self, url: str, filename: str = None) -> str:
        """Capture screenshot of a single URL"""
        if not filename:
            # Generate filename from URL
            safe_name = url.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")
            filename = f"{safe_name}_{int(time.time())}.png"

        filepath = os.path.join(self.output_dir, filename)

        driver = None
        try:
            driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=self.options)
            driver.set_page_load_timeout(self.timeout)
            driver.get(url)

            # Wait a bit for dynamic content
            time.sleep(2)

            driver.save_screenshot(filepath)
            return filename
        except Exception as e:
            print(f"Error capturing screenshot for {url}: {e}")
            return None
        finally:
            if driver:
                driver.quit()

    def capture_batch(self, urls: List[str], on_capture=None) -> List[Dict[str, str]]:
        """Capture screenshots for a list of URLs"""
        results = []
        for url in urls:
            try:
                filename = self.capture_screenshot(url)
                if filename:
                    res = {"url": url, "filename": filename}
                    results.append(res)
                    if on_capture:
                        on_capture(url, res)
            except Exception as e:
                print(f"Error capturing {url}: {e}")
        return results

                filename = self.capture(url)
                if filename:
                    res = {"url": url, "filename": filename}
                    results.append(res)
                    if on_capture:
                        on_capture(url, res) # Signal completion
            except Exception as e:
                print(f"Error capturing {url}: {e}")
        return results

    def capture_poc(self, url: str) -> Dict[str, Any]:
        """Capture screenshot specifically for an exploit Proof of Concept, handling JS alerts safely"""
        safe_name = url.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_").replace("?", "_")[:100]
        filename = f"poc_{safe_name}_{int(time.time())}.png"
        filepath = os.path.join(self.output_dir, filename)
        
        driver = None
        result = {"filename": None, "alert_text": None, "error": None}
        try:
            driver = webdriver.Chrome(service=Service(ChromeDriverManager().install()), options=self.options)
            driver.set_page_load_timeout(self.timeout)
            driver.get(url)
            time.sleep(1.5) # Wait for execution
            
            driver.save_screenshot(filepath)
            result["filename"] = filename
            
        except UnexpectedAlertPresentException as e:
            # This is actually a successful XSS! We caught the alert.
            try:
                alert = driver.switch_to.alert
                result["alert_text"] = alert.text
                alert.accept()
                
                # Take screenshot after accepting alert (shows broken DOM)
                time.sleep(0.5)
                driver.save_screenshot(filepath)
                result["filename"] = filename
            except Exception as inner_e:
                result["error"] = str(inner_e)
                
        except TimeoutException:
            result["error"] = "Timeout while trying to capture PoC"
        except Exception as e:
            print(f"Error capturing PoC screenshot for {url}: {e}")
            result["error"] = str(e)
        finally:
            if driver:
                driver.quit()
                
        return result

if __name__ == "__main__":
    # Test
    surveyor = VisualSurveyor(output_dir="screenshots_test")
    test_url = "https://example.com"
    print(f"Capturing {test_url}...")
    res = surveyor.capture(test_url)
    print(f"Result: {res}")
