from website import create_app
app = create_app()
 
#direct run of main.py
if __name__ == '__main__':
    app.run(debug=True)