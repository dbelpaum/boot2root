import turtle
import re

t = turtle.Turtle()

screen = turtle.Screen()
screen.bgcolor("white")
t.speed(10)

t.penup()
t.goto(0, 0)
t.pendown()

def execute_instructions(instructions):
    for line in instructions.splitlines():
        match = re.match(r"(Avance|Recule) (\d+) spaces", line)
        if match:
            move_type = match.group(1)
            distance = int(match.group(2))
            if move_type == "Avance":
                t.forward(distance)
            elif move_type == "Recule":
                t.backward(distance)
            continue

        match = re.match(r"Tourne (gauche|droite) de (\d+) degrees", line)
        if match:
            turn_direction = match.group(1)
            degrees = int(match.group(2))
            if turn_direction == "gauche":
                t.left(degrees)
            elif turn_direction == "droite":
                t.right(degrees)
            continue

with open('input', 'r') as f:
    instructions = f.read()
execute_instructions(instructions)

turtle.done()