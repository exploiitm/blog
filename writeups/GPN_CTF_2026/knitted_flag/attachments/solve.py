data = []
current_row = []
previous_direction = '-'
with open('pattern.k') as f:
    for line in f:
        line = line.strip()
        
        operation = line.split(' ')
        #We will skip all the other commands other than knit
        if operation[0] != "knit":
            continue

        if operation[1] != previous_direction:
            # If the direction changes, we will append the current_row to data and create a new "row"
            data.append(current_row)
            current_row = []
            
        current_row.append(operation[2])
        previous_direction = operation[1]

from PIL import Image

width = 30
height = len(data)

img = Image.new("RGB", (width, height), "white")
pixels = img.load()

for y, row in enumerate(data):
    for char in row:
        if char[0] == "b":
            needle = int(char[1:])
            pixels[needle, y] = (0, 0, 0)

img = img.rotate(90, expand=True)
img.save("flag.png")
