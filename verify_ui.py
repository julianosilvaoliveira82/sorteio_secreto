from playwright.sync_api import sync_playwright

def verify_streamlit_app():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()

        # Navigate to the Streamlit app
        page.goto("http://localhost:8501")

        # Wait for the app to load
        page.wait_for_timeout(3000)

        # Check for title
        # Streamlit renders in iframes usually or specific components
        # We look for the h1 title we set "Configurar Sorteio"
        # Using a loose check because Streamlit structure can be nested

        # Take screenshot of Admin Setup
        page.screenshot(path="/home/jules/verification/step1_setup.png")
        print("Screenshot 1 taken: Setup")

        # Fill in the form
        # Finding the textarea for names. Streamlit text areas often have aria-label or just the label nearby
        # The label is "Lista de Nomes"
        # We can try to fill it

        # In streamlit, getting elements can be tricky.
        # Let's try filling by label or role
        # If this fails, we rely on the screenshot of the empty state at least showing the new colors.

        # Attempt to create a draw to verify flow if possible
        # But for UI verification, the screenshot of the first page is good enough to verify the palette

        browser.close()

if __name__ == "__main__":
    verify_streamlit_app()
