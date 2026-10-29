# Clickwise: setup and walkthrough (Windows + VS Code)

The project is already built. This guide shows how to run it, understand it and fix common problems.

## 1. What each part does
- **Python** runs the checking logic (`detector.py`).
- **Flask** receives the form and shows pages (`app.py`).
- **HTML templates** are the pages (`templates/`). Flask fills in the score and results.
- **CSS** is the styling (`static/style.css`).
- **unittest** runs the automatic tests (`tests/`).

## 2. Install what you need (one time)
1. **Python**: download from python.org. On the first installer screen, tick **Add python.exe to PATH**, then Install.
   Check in a new terminal: `python --version`
2. **VS Code**: code.visualstudio.com. Install the **Python** extension (the Extensions icon on the left, search "Python").
3. **Git** (for GitHub later): git-scm.com, keep the default options.

## 3. Open the project
1. Unzip `Clickwise.zip` somewhere easy, like `Documents`.
2. In VS Code: **File > Open Folder** and choose the `Clickwise` folder.
3. Open the terminal: **Terminal > New Terminal**.

## 4. Create the environment and run
Type these one at a time:
```
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py
```
After the first two lines you should see `(venv)` at the start of the terminal line.
When the app starts you will see `Running on http://127.0.0.1:5000`. Open that address in your browser.
To stop it, click in the terminal and press **Ctrl + C**.

## 5. Run the tests
In a second terminal (with `(venv)` showing):
```
python -m unittest discover -v
```
Expected ending: `Ran 40 tests ... OK`

## 6. Try these inputs
| Input | What you should see |
|---|---|
| `https://www.example.com/about` | 0, Low Risk, "No configured warning indicators detected." |
| `http://203.0.113.5/secure/login` | 43, Medium Risk |
| `http://paypal.secure-login-verify.example.test@203.0.113.9/login?verify=1` | 75, High Risk |
| `hello` or an empty box | a friendly error message, no crash |

Click **Download report (CSV)** on a result page and open the file in Excel.

## 7. Read the code in this order (15 minutes)
1. `detector.py`: read the settings at the top, then `analyze_url`. Each "Rule:" comment is one check.
2. `app.py`: three routes. `/` shows the form, `/scan` runs the detector, `/download` makes the CSV.
3. `templates/result.html`: see how `{{ result.score }}` is filled in.
4. `tests/test_detector.py`: each test is one example input and the result it should give.

## 8. Try changing something (so you really understand it)
- In `detector.py`, change `SUSPICIOUS_WORDS` (add `"bank"`) and run the tests.
- Change `HIGH_THRESHOLD` from 60 to 50 and see which examples change category.
- Change a colour in `static/style.css` (`--teal`) and refresh the browser.

## 9. Common errors
| Error | Fix |
|---|---|
| `'python' is not recognized` | Reinstall Python with **Add to PATH** ticked, or try `py` instead of `python` |
| `running scripts is disabled on this system` (PowerShell) | Run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`, then activate again. Or open a **Command Prompt** terminal instead |
| `ModuleNotFoundError: No module named 'flask'` | The venv is not active. Run `venv\Scripts\activate`, then `pip install -r requirements.txt` |
| `Address already in use` | Another program uses port 5000. Close the old terminal, or change `port=5000` to `5001` at the bottom of `app.py` |
| `TemplateNotFound` | The folder must be named exactly `templates` and sit next to `app.py` |
| Page has no styling | The folder must be named exactly `static`. Hard refresh with Ctrl + F5 |
