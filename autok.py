import json,re,threading,sys,os
import fnmatch,shutil,subprocess
from pathlib import Path
import openai
from neuroengine import Neuroengine
import FreeSimpleGUI as sg


default_config = [{"name": "Detect buffer overflows", "prompt": "Check this code for any out-of-bounds vulnerability."},
                  {"name": "Detect integer overflows", "prompt": "Check this code for any integer-overflow vulnerability."},
                  {"name": "Detect format-string vulns", "prompt": "Check this code for format-strings vulnerabilities."}
                 ]

config_file = 'AK-rules.json'

# Thanks Sonnet 3.5
def print_ai_hacker():
    ascii_art = '''
  _____
 /     \\  AI
|  o o  | ___
| \\___/ |/   \\
|__   __|     |
   | | | 01001|
 __|_|_|_____/
|           |
|  HACK.exe |
|___________|
'''
    print(ascii_art)


def print_whitehat_hacker():
    ascii_art = '''
   _____
  /     \\
 | () () | <PATCH>
 |  ___  |/
 | |   | |
 | |FIX| |/"""\\
 |_|___|_|     |
 |  ___  | BUG |
 | |   | |     |
 |_|___|_|_____|
'''
    print(ascii_art)

# Call free Neuroengine service
def call_neuroengine(prompt,service_name):
    hub=Neuroengine(service_name=service_name)
    answer=hub.request(prompt=prompt,raw=False,temperature=0.2,max_new_len=512,seed=5)
    return(answer)


def check_api_key_validity(api_key):
   try:
        openai.api_key = api_key
        ml=openai.Model.list()
        print("\t[I] OpenAI API key is valid")
   except openai.OpenAIError as e:
       print("\t[E] Invalid OpenAI API key: "+str(e))
       exit(-1)

api_key=""
# import api key
def read_apikey():
    global api_key
    api_key = os.environ.get("OPENAI_API_KEY")
    if api_key is None: api_key=""
    if (len(api_key)==0): # try to load apikey from file
        try:
            api_key=open('api-key.txt','rb').read().strip().decode()
        except:
            print("\t[E] Couldn't load OpenAI Api key, please load it in OPENAI_API_KEY env variable, or alternatively in 'api-key.txt' file.")
            exit(-1)

# Call OpenAI model
def call_openai(prompt,model):
        global api_key
        # Load API key if needed
        if api_key=="":
            read_apikey()
            check_api_key_validity(api_key)

        # Call OpenAI API
        response = openai.ChatCompletion.create(
            model=model,
            messages =[
                {'role':'system','content':'You are an expert security researcher, programmer and bug finder. You analize every code you see and are capable of finding programming bugs at an expert or super-human level.'},
                {'role':'user','content':prompt}
                ],
            temperature=0.2,
            max_tokens=1024)
        return response.choices[0]['message']['content']

# Crude C code parser

def parse_c_functions(code):
    if code is None:
        return
    functions = []
    
    # Define a regex pattern for C function headers
    function_header_pattern = re.compile(r'\b[\w\s\*]+\s+\w+\s*\([^)]*\)\s*\{')
    
    # Find all function headers
    matches = function_header_pattern.finditer(code)
    
    # Track the positions of function bodies
    for match in matches:
        header_start = match.start()
        start_pos = match.end() - 1  # Start after the opening brace
        brace_count = 1
        pos = start_pos
        
        # Traverse the code to find the matching closing brace
        while (brace_count > 0) and (pos <= len(code)):
         try:
            pos += 1
            if code[pos] == '{':
                brace_count += 1
            elif code[pos] == '}':
                brace_count -= 1
         except: break
        
        # Extract the function header and body
        function_header = code[header_start:start_pos ]
        function_body = code[start_pos:pos+1]
        full_function = function_header + function_body
        
        functions.append((full_function,function_header))
    
    return functions

# Code text handling functions

def find_line_number(text, substring):
    lines = text.splitlines()
    temp_string=''
    for i, line in enumerate(lines, start=1):
        temp_string += line+"\n"
        if substring in temp_string:
            return i
    return None 

def get_file_text(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            text = file.read()
            return text
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        return None
    except Exception as e:
        print(f"Error loading file: {e}")
        return None

def insert_text_at_line(file_path, line_number, text_to_insert):
    try:
        with open(file_path, 'r+', encoding='utf-8') as file:
            lines = file.readlines()
            if line_number > len(lines):
                print(f"Error: Line {line_number} does not exist in the file.")
                return
            lines.insert(line_number - 1, text_to_insert + '\n')
            file.seek(0)
            file.writelines(lines)
            file.truncate()
    except Exception as e:
        print(f"Error inserting text: {e}")

def add_report_to_file(filename, function_line, report, function):
    reportfile = f"{filename}.report.md"

    # Determine the mode to open the file
    mode = 'a' if os.path.exists(reportfile) else 'w'

    with open(reportfile, mode) as file:
        if mode == 'w':
            file.write(f"## AutoK report for file {filename}\n")

        file.write(f"## Report for line {function_line}\n")
        file.write(f"{report}\n")
        file.write(f"```cpp\n{function}\n```\n")

# Execute LLM and retrieve results
def callAI(function,filename,count,total,service_name,embed_report=True):
        global issues
        global rulesprompt
        function=function[0]
        print(f'[I]\tProcessing function {filename}: {count}/{total}')
        prompt='You are an expert security researcher, programmer and bug finder. You analize every code you see and are capable of finding programming bugs at an expert or super-human level.\n'
        prompt+=f'Explain the bugs in a very concise way. Report only exploitable critical bugs. If a critical bug is found, prefix it with the word "FIXME:". Perform the following exhaustive checks on the code:\n{rulesprompt}\n{function}'
        if service_name.startswith("gpt"):
            report=f'\n/*------AutoK Report - Model: {service_name} ------\n{call_openai(prompt,service_name)}\n----------------*/\n'
        else:
            report=f'\n/*------AutoK Report - Model: {service_name} ------\n{call_neuroengine(prompt,service_name)}\n----------------*/\n'
        if report.find("FIXME")>-1:
            issues+=1
        res = get_file_text(filename)
        function_line=find_line_number(res,function)-len(function.splitlines())+1
        if function_line>0:
            if embed_report:
                insert_text_at_line(filename,function_line,report)
            else:add_report_to_file(filename,function_line,report,function)
        print(f'-->Finished report {count}/{total}')


def find_c_cpp_files(directory):
    c_cpp_files = []
    # Walk through the directory
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(('.c', '.cpp', '.cc', '.cxx', '.h', '.hpp', '.hh', '.hxx')):
                c_cpp_files.append(os.path.join(root, file))

    return c_cpp_files

def processFilename(filename,window,service_name,embedReport):
            res = get_file_text(filename)
            function_bodies = parse_c_functions(res)
            # Analyze each function
            count=0
            for function in function_bodies:
                count+=1
                window['dynamic_text'].update(f'{filename}: Function bodies: {len(function_bodies)} Processing {count}/{len(function_bodies)} Possible Issues: {issues}')
                res = get_file_text(filename)
                try:
                    function_line=find_line_number(res,function[0])-1
                except: function_line=0
                if function_line<0: continue
                callAI(function,filename,count,len(function_bodies),service_name,embedReport)
                window['progress_bar'].update_bar((100.0/len(function_bodies))*count)


def launchKakGUI(filename):
    global issues
    global rules
    global rulesprompt
    #Read available free models from Neuroengine
    ne=Neuroengine("")
    try:
        models=ne.getModels()
    except:
        models=[]
    LLMOptions=[]
    # Hardcoded OpenAI Models
    LLMOptions.append("gpt-3.5-turbo")
    LLMOptions.append("gpt-4-0613")
    LLMOptions.append("gpt-4o")
    for model in models:
        if model['connected']==True:
            LLMOptions.append(model['name'])

    # Create a list of checkboxes for each rule
    checkboxes = []
    for i, rule in enumerate(rules):
        checkbox = sg.Checkbox(rule["name"], key=f"rule_{i}", default=True)
        checkboxes.append([checkbox])
    # Create a text box for entering a custom rule
    custom_rule_input = sg.InputText(key='custom_rule', size=(30,1))
    # Create a frame panel for the checkboxes
    frame_layout = [
        [sg.Text("Select Rules:")],
        *checkboxes,
        [sg.Text("Enter Custom Rule:")],
        [custom_rule_input]
        ]
    frame = sg.Frame("Rule Selection", frame_layout, title_color="blue")

    # Define the layout
    layout = [
        [sg.Push(),sg.Text(f'Filename: {filename}',font=('Helvetica', 12, 'bold'),justification='center'),sg.Push()],
        [sg.Text('Select a model:')],
        [sg.Combo(LLMOptions, key='option',default_value="Neuroengine-Medium",size=(30,1))],
        #[frame],
        [sg.Push(), sg.Column([[frame]], justification='center'), sg.Push()],
        [sg.Checkbox('Embed report in file', key=f"embed", default=True)],
        [sg.Text('Progress:', key='dynamic_text')],
        [sg.ProgressBar(100, size=(50, 20), key='progress_bar', visible=True)],
        [sg.Push(),sg.Button('Launch'), sg.Button('Cancel'),sg.Push()]
        ]
    # Create the window
    window = sg.Window('AutoKaker V1', layout, finalize=True)
    window['progress_bar'].update(visible=False)
    
    if Path(filename).is_file():
        # Extract function bodies
        res = get_file_text(filename)
        function_bodies = len(parse_c_functions(res))
        window['dynamic_text'].update(f'Function bodies: {function_bodies}')
    else:
        # Search all files and count function bodies
        files=find_c_cpp_files(filename)
        function_bodies=0
        for f in files:
            res = get_file_text(f)
            function_bodies += len(parse_c_functions(res))
        window['dynamic_text'].update(f'Files: {len(files)}, Function bodies: {function_bodies}')

    while True:
        event, values = window.read()
        if event in (None, 'Cancel'):
            break
        elif event == 'Launch':
            count=0
            issues=0
            # ---LAUNCH pressed
            window['progress_bar'].update(visible=True)
            window['option'].update(disabled=True)
            window['Launch'].update(disabled=True)
            # Assemble the rules
            rulesprompt=""
            c=0
            for i in range(len(rules)):
                c+=1
                if values[f"rule_{i}"]:
                    rulesprompt+=f"{c}.{rules[i]['prompt']}\n"
            if len(values['custom_rule'])>0:
                rulesprompt+=f"{values['custom_rule']}\n"
            # Find bugs
            if Path(filename).is_file():
                processFilename(filename,window,values["option"],values["embed"])
            else:
                # Search all files and count function bodies
                files=find_c_cpp_files(filename)
                for f in files:
                    processFilename(f,window,values["option"],values["embed"])
    return


def loadConfig():
    global rules
    if not os.path.exists(config_file):
        with open(config_file, 'w') as f:
            json.dump(default_config, f, indent=4)

    with open(config_file, 'r') as f:
        rules = json.load(f)   

# Function to find files
def find_files(root_dir):
    matching_files = []

    for dirpath, dirnames, filenames in os.walk(root_dir):
        for filename in filenames:
            if fnmatch.fnmatch(filename, '*.c'):
                matching_files.append(os.path.join(dirpath, filename))

    return matching_files

# Execute feedback command to check if modifications are correct
def tryCompile(makecmd):
    global currentfilename
    try:
        subprocess.check_call([makecmd],shell=True)
        print("\t[I] ---------- Make succeeded")
        return(True)
    except subprocess.CalledProcessError as e:
        print(f"\t[E] -------- Make failed with return code {e.returncode}")
        return(False)

# Main Patcher GUI
def launchPatchGUI(path,makecmd):
    #Read available models
    ne=Neuroengine("")
    try:
        models=ne.getModels()
    except:
        models=[]
    LLMOptions=[]
    LLMOptions.append("gpt-3.5-turbo")
    LLMOptions.append("gpt-4-0613")
    LLMOptions.append("gpt-4o")
    for model in models:
        if model['connected']==True:
            LLMOptions.append(model['name'])
    defaultPrompt='Add code checks to this function to avoid any out-of-bounds or integer-overflow vulnerability.'
    # Define the layout
    # Create a text box for entering a custom rule
    custom_prompt_input = sg.Multiline(key='custom_rule', size=(30,10),
                                       default_text=defaultPrompt)

    layout = [
        [sg.Push(),sg.Text(f'Path: {path}',font=('Helvetica', 12, 'bold'),justification='center'),sg.Push()],
        [sg.Text('Select a model:')],
        [sg.Combo(LLMOptions, key='option',default_value="Neuroengine-Medium",size=(30,1))],
        [sg.Text("Modification Prompt:")],
        [custom_prompt_input],
        [sg.Text('Progress:', key='dynamic_text')],
        [sg.ProgressBar(100, size=(50, 20), key='progress_bar', visible=True)],
        [sg.Push(),sg.Button('Launch'), sg.Button('Cancel'),sg.Push()]
        ]
    # Create the window
    window = sg.Window('AutoPatcher V1', layout, finalize=True)
    window['progress_bar'].update(visible=False)
    # Call the function with the current directory as the root
    current_directory = path
    files = find_files(current_directory)
    print(f"\t[I] ---- Amount of files: {len(files)}")
    window['dynamic_text'].update(f'Files: {len(files)}')
    use_openai=False
    while True:
        event, values = window.read()
        if event in (None, 'Cancel'):
            break
        elif event == 'Launch':
            # ---LAUNCH pressed
            window['progress_bar'].update(visible=True)
            window['option'].update(disabled=True)
            window['Launch'].update(disabled=True)
            # Print the matching file paths
            global currentfilename
            count=0
            for file_path in files:
                window['progress_bar'].update_bar((100.0/len(files))*count)
                count+=1
                currentfilename=file_path
                start=True
                if not start:
                    continue
                try:
                    a=open(file_path)
                    c_code=a.read()
                    a.close()
                except: pass
                # Extract function bodies
                try:
                    function_bodies = parse_c_functions(c_code)
                except:
                    print(f"\t[E] ---- Malformed file: {file_path}")
                    continue
                print(f"\t[I] ---- Processing {file_path}, total functions: {len(function_bodies)}")
                for function in function_bodies:
                    code=f"{function[1]}"
                    print(f"\t[I] ---- {function[1]}")
                    prompt=f'{values["custom_rule"]} - Write only the c function, nothing else. The new function must be 100% compatible, do not add new functions nor comments:\n {function[0]}\n'
                    model_name=values["option"]
                    if model_name.startswith("gpt"):
                        use_openai=True
                    if use_openai==True:
                        response=call_openai(prompt,model_name)
                        newfunction=response[response.find(function[1]):]
                    else:
                        response= call_neuroengine(prompt,model_name)
                        newfunction=response[response.find(function[1]):]
                    print(newfunction)
                    try:
                        newfunction=parse_c_functions(newfunction)
                        newfunction=newfunction[0]
                        newfunction=newfunction[0]
                    except:
                        print(f"\t[E] ----- Malformed refactor.")
                        continue
                    print(f"\t[I] ----- New function!")
                    # Make copy of function
                    print(f'\t[I] ------- Copying {file_path} to {file_path+".bak"}')
                    shutil.copyfile(file_path,file_path+".bak")
                    # Replace function with new candidate
                    a=open(file_path,"rb")
                    code=a.read()
                    a.close()
                    code = code.decode()
                    code=code.replace(function[0],newfunction)
                    code = code.encode()
                    # Save patched file
                    a=open(file_path,"wb")
                    a.write(code)
                    a.close()
                    if makecmd:
                        print("\t[I] -------- Compiling...")
                        if tryCompile(makecmd)==False: #compilation failed, replace file with backup
                            shutil.copyfile(file_path+".bak",file_path)
                    os.unlink(file_path+".bak") #clean
            


import argparse
def main():
    # Banner
    # Create the parser
    parser = argparse.ArgumentParser(description="AutoKaker v1.0: Simple LLM bug hunter/autopatcher")

    # Add the required argument (path)
    parser.add_argument("path", type=str, help="The path to a file or directory")

    # Add the optional argument ('--patch')
    parser.add_argument('--patch', action='store_true', help="Activate patch mode")

    # Feedback command
    parser.add_argument('--make', type=str, help="Feedback command")

    # Parse the arguments
    args = parser.parse_args()

    loadConfig()
    if args.patch:
        print_whitehat_hacker()
        launchPatchGUI(args.path,args.make)
    else:
        print_ai_hacker()
        launchKakGUI(args.path)



if __name__ == "__main__":
    main()
