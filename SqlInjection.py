from Injection import *
from selenium import webdriver
from selenium.common.exceptions import UnexpectedAlertPresentException, NoSuchElementException
from selenium.webdriver.common.by import By

class SqlInjection(Injection):
    def __init__(self, session, payloadPath, urls):
        super().__init__(session, urls, "SQL Injection")
        if payloadPath:
            self.payloads = self.Get_payloads(payloadPath)
        else: 
            self.payloads = self.Get_payloads('payload/sqli_min.txt')
            print("Scanning For SQL Vulnerabilities :")
        self.driver = self.CreateDriver()

    def CheckFault(self, payload, response_html_doc, response_status_code):
        err_list = [
            'You have an error in your SQL syntax',
            'Warning: mysql_fetch_array()',
            'Warning: mysql_fetch_assoc()',
            'Warning: mysql_num_rows()',
            'Warning: mysql_query()',
            'Warning: pg_exec()',
            'Warning: pg_query()',
            'Unclosed quotation mark after the character string',
            'SQLSTATE[HY000]'
        ]
        
        # Check for SQL error messages in the response
        for err in err_list:
            if err in response_html_doc:
                print(f"Found SQL error '{err}' in response.")
                return True
        
        # Check for HTTP 500 status code
        if response_status_code == 500:
            print("Received HTTP error code, indicating a possible server error due to SQL injection.")
            return True
        
        print("No SQL error or HTTP error code found in response.")
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
        # Skip the specified URL
        if href.startswith("http://localhost/DVWA/"):
            if href != "http://localhost/DVWA/vulnerabilities/sqli/":
                return False


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
                response_html_doc = self.driver.page_source

                # Check status code of the resulting page
                response_status_code = self.driver.execute_script("return document.readyState") == "complete" and self.driver.execute_script("return document.status") or 500
                fault = self.CheckFault(payload, response_html_doc, response_status_code)
                if fault: 
                    self.PrintErr("SQL Injection", href, params.loc[selected_input, 'name'], payload)
                    return True

                self.driver.get(new_url_encoded)
                response_html_doc = self.driver.page_source

                # Check status code of the resulting page
                response_status_code = self.driver.execute_script("return document.readyState") == "complete" and self.driver.execute_script("return document.status") or 500
                fault = self.CheckFault(payload, response_html_doc, response_status_code)
                if fault: 
                    self.PrintErr("SQL Injection", href, params.loc[selected_input, 'name'], payload)
                    return True
 
            elif formMethod.upper() == 'POST':
                inputname = params.loc[selected_input, 'name']
                try:
                    inputbox = self.driver.find_element(By.NAME, inputname)
                    if params.loc[selected_input, 'type'] in ['text'] or params.loc[selected_input, 'tag'] =='textarea':
                        # Inject payload
                        inputbox.send_keys(payload)

                        try:  
                            submitBtns = params[params['type'] == 'submit'].iloc[0]
                            submitBtn_name = submitBtns['name']
                            
                            if submitBtn_name:
                                self.driver.find_element(By.NAME, submitBtn_name).click()
                            else:
                                submitbtn = [i for i in self.driver.find_elements(By.TAG_NAME, 'input') if i.get_attribute('type') == 'submit'][0]
                                submitbtn.click()

                        except UnexpectedAlertPresentException:
                            self.PrintErr("SQL Injection", href, params.loc[selected_input, 'name'], payload)
                            self.driver.close()
                            self.driver = self.CreateDriver()
                            return True
                except NoSuchElementException:
                    print(f"Element with name '{inputname}' not found. Skipping...")
                    continue  # Move to the next iteration

            # Check status code of the resulting page after all injections
            response_html_doc = self.driver.page_source
            response_status_code = self.driver.execute_script("return document.readyState") == "complete" and self.driver.execute_script("return document.status") or 500
            fault = self.CheckFault(payload, response_html_doc, response_status_code)
            if fault: 
                self.PrintErr("SQL Injection", href, params.loc[selected_input, 'name'], payload)
                return True

        return False

if __name__ == "__main__":
    # Add your testing or example code here
    pass
