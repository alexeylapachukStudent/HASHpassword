# HASHpassword


## How to Run

1. **Create a Virtual Environment**  
   Create a virtual environment in your project's root directory. This isolates your project's dependencies from the global Python environment.

   ```bash
   python3 -m venv venv

   
2. **Activate the Virtual Environment**  
   Activate the virtual environment to use its isolated environment for your project dependencies.

  #### On macOS and Linux:
  ```bash
  source venv/bin/activate
  ```

  #### On Windows:
  ```bash
  venv\Scripts\activate
  ```


3. **Install Dependenciest**  
   Install all the dependencies listed in the `requirements.txt` file using pip:

   ```bash
   pip install -r requirements.txt

4. **Set Up Environment Variables**  
   If your project uses environment variables, create a `config.json` file in the project's root directory and add the required variables. For example:

   ```bash
   FERNET_KEY=HaytxFPcnr9OC3waOFuOKLMjWE1HIsafPE6KxfarJV0=


5. **Run the project**  
   Now you can run your project. For example, if you have a `main.py` file, execute the following command:

   ```bash
   python main.py



   
