from requests.sessions import default_headers
from Injection import *
from selenium import webdriver
from selenium.common.exceptions import UnexpectedAlertPresentException, NoSuchElementException
from selenium.webdriver.common.by import By

default_payloads = ['<script>alert(123);</script>', '<ScRipT>alert("XSS");</ScRipT>', '<script>alert(123)</script']

class XssInjection(Injection):
    def __init__(self, session, payloadPath, urls):
        super().__init__(session, urls, "XSS Injection")
        if payloadPath:
            self.payloads = self.Get_payloads(payloadPath)
        else: 
            self.payloads  = self.Get_payloads('payload/xss_min.txt')
            print("Scanning For XSS Vulnerabilities :")
        self.driver = self.CreateDriver()

    def CheckFault(self):    
        try: 
            html_doc = self.driver.page_source        
        except UnexpectedAlertPresentException:
            self.driver.close()
            self.driver = self.CreateDriver()
            return True
        return False

    def CreateDriver(self):
        options = webdriver.ChromeOptions()
        options.headless = True
        options.add_argument("--enable-javascript")
        options.add_experimental_option('excludeSwitches', ['enable-logging'])
        driver = webdriver.Chrome(options=options)
        driver.implicitly_wait(3)

        driver.get(self.urls[0])
            
        cookie_dict = self.session.cookies.get_dict()
        for key, value in cookie_dict.items():
            driver.add_cookie({'name' : key, 'value' : value})
        return driver

    def PayloadInjection(self, params, selected_input, url, href, formMethod):
        params_dict = {}
        for i in range(len(params)):
            if not ((not params.loc[i, 'name']) and (params.loc[i, 'type'].lower() == 'submit')):
                params_dict[params.loc[i, 'name']] = params.loc[i, 'value']

        for payload in self.payloads:
            self.driver.get(url) 

            if formMethod.upper() == 'GET':
                params_dict[params.loc[selected_input, 'name']] = payload
                new_url = self.add_url_params(href, params_dict)
                new_url_encoded = self.add_url_params_encoded(href, params_dict)

                self.driver.get(new_url)
                fault = self.CheckFault()
                if fault: 
                    self.PrintErr("Xss Injection", href, params.loc[selected_input, 'name'], payload)
                    return True

                self.driver.get(new_url_encoded)
                fault = self.CheckFault()
                if fault: 
                    self.PrintErr("Xss Injection", href, params.loc[selected_input, 'name'], payload)
                    return True
 
            elif formMethod.upper() == 'POST':
                inputname = params.loc[selected_input, 'name']
                try:
                    inputbox = self.driver.find_element(By.NAME, inputname)
                    if params.loc[selected_input, 'type'] in ['text'] or params.loc[selected_input, 'tag'] =='textarea':
                        inputbox.send_keys(payload)

                        try:  
                            submitBtns = params[params['type'] == 'submit'].iloc[0]
                            submitBtn_name = submitBtns['name']
                            
                            if submitBtn_name:
                                self.driver.find_element(By.NAME, submitBtn_name).click()
                            else :
                                submitbtn = [i for i in self.driver.find_elements(By.TAG_NAME, 'input') if i.get_attribute('type') == 'submit'][0]
                                submitbtn.click()

                        except UnexpectedAlertPresentException:
                            self.PrintErr("Xss Injection", href, params.loc[selected_input, 'name'], payload)
                            self.driver.close()
                            self.driver = self.CreateDriver()
                            return True
                except NoSuchElementException:
                    print(f"Element with name '{inputname}' not found. Skipping...")
                    continue  # Move to the next iteration

            fault = self.CheckFault()
            if fault: 
                self.PrintErr("Xss Injection", href, params.loc[selected_input, 'name'], payload)
                return True

        return False

if __name__ == "__main__":
    # Add your testing or example code here
    pass
