+++
title = "1.1 Basic Python Programming"
[taxonomies]
tags = ['scripting', 'Python Programming']
+++

## Simple Operations

Python has the capability of carrying out calculations. Enter a calculation directly into a print statement:

```py
print(2 + 2)
print(5 + 4 -3)
```

> The spaces around the plus and the minus signs here are optional (the code would work without them) but they make it easier to read.

Python also carries out multiplication and division, using an **asterisk** `*` to indicate multiplication and a **forward slash** `/` to indicate division.

Use **parentheses** to determine which operations are performed first.

```py
print(2*(3+4))
print(10/2)
```

> Using a single slash to divide numbers produces a decimal (or **_float_**, as it is called in programming). We’ll learn more about **floats** later.

Dividing by zero produces an **error** in python, as no answer can be calculated.

```py
print(11/0)
```

```
Traceback(most recent call last):
File"\<stdin\>", line 1, in \<module\>
ZeroDivisionError: division by zero
```

> In python, the last line of an error message indicates the error’s type. Read error messages carefully, as they often tell you how to fix a program!

## Floats

**Floats** are used in python to represent numbers that **aren’t integers** (whole numbers). Some examples of numbers that are represented as floats are 0.5 and -7.8538953. They can be created directly by entering a number with a decimal point, or by using operations such as division on integers.

```py
print(3/4)
```

> Computers can’t store floats perfectly accurately, in the same way we can’t write down the complete decimal expansion of 1/3 (0.333333333…). Keep this in mind, because it often leads to infuriating bugs!

A float is also produced by running an operation on two floats, or on a float and an integer.

> A float can be added to an integer, because Python silently converts the ineger to a float.

## Exponentiation

Besides addition, subtraction, multiplication, and division, Python also supports exponentiation, which is raising of one number to the power of another. This operation is performed using two asterisks.

```py
print(2**5)
print(9**(1/2))
```

> You can chain exponentiation together. In other words, you can raise a number to multiple powers. Eg. 2**3**2

## Quotient

**Floor division** is done using two forward slashes and is used to determine the **quotient** of a division (the quantity produced by the division of two numbers).

**For example:**

```py
print(20//6)
```

The code above will output 3. 
> You can also use floor division on floats

## Remainder

The **modulo operator** is carried out with a percent symbol `%` and is used to get the **remainder** of a division.

For example:

```py
print(20%6)
print(1.25%0.5)
```

> All numerical operators can also be used with floats.

## Strings

If you want to use text in python, you have to use a string. A string is created by entering text between **two single or double quotation marks**.

```py
print("Python is fun!")
print("Always look on the bright side")
```

> The delimiter (” or ’) used for a string doesn’t affect how it behaves in any way.

### Backslash

Some characters cant be directly included in a string. For instance, double quotes can’t be directly included in a double quote string; this would cause it to end prematurely.

Characters like double quotes must be escaped by placing a **backslash** before them. Double quotes need to be escaped in double quotes strings only, and the same is true for single quotes strings. For Example:

```py
print('Brian\'s mother: He\'s not an angel. He\'s a naughty boy!')
```

> Backslashes can also be used to escape tabs, arbitrary Unicode characters, and various other things that can’t be reliably printed.

Newlines

`\n` represents a new line. It can be used in strings to create multi-line output.

```py
print('One **\n** Two **\n** Three')
```

Newlines will automatically be added for strings that are created using three quotes.

```py
print("""This
is a
multiline
text""")
```
> Similarly, `\t` represents a tab.

### Concatenation

As with integers and floats, strings in Python can be added, using a process called _concatenation_, which can be done on any two strings.

```py
print("Spam" + 'eggs')
```

> When concatenating strings, it doesn’t matter whether they have been created with single or double quotes, as seen above

> Adding a string to a number produces an error, as even though they might look similar, they are two different entities

### String Operations

Strings can also be **multiplied** with integers. This produces a repeated version of that string. The order of the _string_ and the _integer_ doesn’t matter, but the string usually comes first.

```py
print("spam"*3)

print(4*'2')
```

> Strings can’t be multiplied with other strings. Strings also can’t be multiplied by floats, even if the floats are whole numbers.

## Variables

A _variable_ allows you to store a value by assigning it to a name, which can be used to refer to the value later in the program. For example, in game development, you would use a variable to to store the points of the player.

To assign a variable, use **one equals sign**.

```py
user = "James"
```

You can use variables to perform corresponding operations, just as you did with numbers and strings:

```py
x = 7
print(x)

print(x + 3)
print(x)
```

> The variable stores its value throughout the program.

Variables can be assigned as many times as you want, in order to change their value. In python, variables don’t have specific types, so you can assign a string to a variable, and later assign an integer to the same variable.

```py
x = 123.456
print(x)

x = "This is a string"
print(x+"!")
```

> However, this is not a good practice. To avoid mistakes, try to avoid overwriting the same variable with different data types.

### Variable Names

Certain restrictions apply in regard to the characters that may be used in python variable names. The only characters that are allowed are **letters, numbers and underscore**. Also, they can’t start with numbers. Not following these rules results in errors.

```py
this_is_a_normal_name = 7

123abc = 7
```

```
SyntaxError: invalid syntax
```

> Python is a case sensitive programming language. Thus, `lastname` and `Lastname` are two _different_ variable names in python.

You can use the *del* statement to remove a variable, which means the reference from the name to the value is deleted, and trying to use the variable causes an error.

```py
foo = 3
del foo
print(foo)
# results in an error
```

Deleted variables can also e reassigned to later as normal.

```py
foo = 2
bar = 3
del bar
bar = 8
print(foo + bar)
```

> The variables foo and bar are called metasyntactic variables, meaning they are used as placeholder names in example code to demonstrate something.

## Input

To get input from the user in python, you can use the intuitively named input function. For example, a game can ask for a user’s name and age as input and use them in the game.

The input function prompts the user for input, and returns what they enter as a string (with the contents automatically escaped).

```py
x = input()
print(x)
```

> Even if the user enters a number as an input, it is processed as a string.

The input statement needs to be followed by parentheses. You can provide a string to `input()` between the parentheses, producing a prompt message.

```py
name = input("Enter your name: ")
print("Hello"+name)
```
    
> The prompt message helps clarify what the input is asking for.

To convert the string to a number, we can use the `int()` function:

```py
age =int(input())
print(age)
```

Similarly, in order to convert a number to a string, the str() function is used. This can be useful if you need to use a number in string concatenation. For example:

```py
age = 42
print("His age is" + str(age))
```

> You can convert to float using the float() function.

You can take input multiple times to take multiple user input. For example:

```py
name = input()
age = input()

print(name + "is" + age)
```

> When input function executes, program flow stops until the user enters some value.

## In Place Operators

In-place operators allow you to write code like `x = x + 3` more concisely as `x +=3`. The same thing is possible with other operators such as `-`,`*`, `/`, and `%` as well.

```py
x = 2
print(x)

x += 3
print(x)
```

These operators can be used on types other than numbers, as well, such as strings.

```py
x= "spam"
print(x)

x += "eggs"
print(x)
```
> In-place operators can be used for any numerical operation (+,-,*,/,%,**,//).

## Booleans

Another type in python is the **Boolean** type. There are two Boolean values: `True` and `False`. They can be created by comparing values, for instance by using the equal to `==`.

```py
my_boolean = True
print(my_boolean)
True

print(2 == 3)
False

print("hello" == 'hello')
True
```
    
> Be careful not to confuse assignment (one equal sign) with comparison (two equal signs).

## Comparison

Another comparison operator, the *not* equal operator (!=), evaluates to True if the items being compared aren’t equal, and False if they are.

```py
print(1 != 1)
False

print("eleven" != "seven")
True

print(2 != 10)
True
```
    
> Comparison operators are also called relational operators.

Python also has operators that determine whether one number (float or integer) is greater than or smaller than another. These operators are `>` and `<` respectively.

```py
print(7 > 5)
True

print(10 < 10)
False
```

> Different numeric types can also be compared, for example, integer and float.

The greater than or equal to, and the smaller than or equal to operators are >= and <=. They are the same as the strict greater than and smaller than operators, except that they return True when comparing equal numbers.

```py
print(7<= 8)
True

print(9>=9.0)
True
```

Greater than and smaller than operators can also be used to compare strings *lexicographically*. For Example:


```py
print("Annie" > "Andy")
True
```

## If statements

You can use if statements to run code if a certain condition holds. If the expression evaluates to True, some statements are carried out.Otherwise they aren’t carried out. An if statement looks like this:

if expression:
<br>    statements

> Python uses indentation, (white spaces at the beginning of a line) to delimit blocks of code. Depending on the program’s logic, indentation can be mandatory. As you can see, the statements in the if should be indented.

Here is an example of if statement:

```py
if 10 > 5:
    print("10 is greater than 5")

print("The program ended")
```

The expression determines whether 10 is greater than 5. Since it is, the indented statement runs, and “10 is greater than 5” is output. Then, the unindented statement, which is not a part of the if statement, is run, and “Program ended” is displayed.

> Notice the colon at the end of the expression in the if statement.

To perform more complex checks, if statements can be nested, one inside the other. This means that the inner if statement is the statement part of the outer one. This is one way to see whether multiple conditions are satisfied.

For example:

```py
num = 12
if num > 5:
    print("Bigger than 5")
    if num <= 47:
        print("between 5 and 47")
```

> Indentation is used to define the level of nesting.

## else Statements

The _if_ statement allows you to check a condition and run some statements, if the condition is True. The _else_ statement can be used to run some statements when the condition of the if statement is False.

As with if statements, the code inside the block should be indented.

```py
x = 4
if x == 5:
    print("Yes")
else:
    print("No")
```

> Notice the colon after the else keyword.

Every if condition block can have only one else statement. In order to make multiple checks, you can chain if and else statements.

For example, the following program checks and outputs the num variable’s value as text:

```py
num = 3
if num == 1:
    print("One")
else:
    if num == 2:
        print("Two")
    else:
        if num == 3:
            print("Three")
```
    
> Indentation determines which if/else statements the code blocks belong to.

## elif Statements

Multiple if/else statements make the code long and not very readable. The elif (short for else if) statement is a shortcut to use when chaining if and else statements, making the code shorter.

The same example from the previous part can be rewritten using elif statements:

```py
num = 3:
if num == 1:
    print("One")
elif num == 2:
    print("Two")
elif num == 3:
    print("Three")
else:
    print("None are true")
```

As you can see in the example above, a series of if elif statements can have a final else block, which is called if none of the if or elif expressions is True. >The elif statement is equivalent to an else/if statement. It is used to make the code shorter, more readable, and avoid indentation increase.

## Boolean Logic

Boolean logic is used to make more complicated conditions for if statements that rely on more than one condition. Python’s Boolean operators are and, or, and not. The `and` operator takes two arguments, and evaluates as True if, and only if, both of its arguments are True. Otherwise, it evaluates to False.

```py
print( 1 == 1 and 2 == 2)
True

print(1 == 1 and 2 == 3)
False

print( 1 != 1 and 2 > 3)
False

print( 2 < 3 and 3 > 6)
False
```

> Boolean operators can be used in expression as many times as needed.

The `or` operator also takes two arguments. It evaluates to True if either (or both) of its arguments are True, and False if both arguments are False.

```py
print( 1 == 1 or 2 == 2)
True

print(1 == 1 or 2 == 3)
True

print( 1 != 1 or 2 > 3)
False

print( 2 < 3 or 3 > 6)
True
```


> Besides values, you can also compare variables.

Unlike other operators we’ve seen so far, `not` only takes one argument, and inverts it. The result of not True is False, and not False goes to True

```py
print( not 1 == 1)
False

print( not 1 > 7)
True
```

> You can chain multiple conditional statements in an if statement using the Boolean operators.

## Operator Precedence

Operator precedence is a very important concept in programming. It is an extension of the mathematical idea of order of operations (multiplication being performed before addition, etc.) to include other operators, such as those in Boolean logic.

The below code shows that == has a higher precedence than or

```py
print(False == False or True)
True

print(False == (False or True))
False

print((False == False) or True)
True
```

> Python’s order of operations is the same as that of normal mathematics: parentheses first, then exponentiation, then multiplication/division, and then addition/subtraction.

## Chaining Multiple Conditions

You can chain multiple conditional statements in an if statement using the Boolean operators.

For example, we can check if the value of a grade is between 70 and 100:

```py
grade = 88
if (grade >= 70 and grade <= 100):
    print("Passed!")
```
    
> You can use multiple and, or, not operators to chain multiple conditions together.

## Lists

Lists are used to store items. A list is created using square brackets with commas separating items.

```py
words = ["Hello", "world", "!"]
```

In the example above the words list contains three string items.

A certain item in the list can be accessed by using its index in square brackets.

For example:

```py
words = ["Hello", "world", "!"]
print(words[0])
print(words[1])
print(words[2])
```

> The first list item’s index is 0, rather than 1, as might be expected.

Sometimes you need to create an empty list and populate it later during the program. For example, if you are creating a queue management program, the queue is going to be empty in the beginning and get populated with people data later.

An empty list is created with an empty pair of square brackets.

```py
empty_list = []
print(empty_list)
```

> In some code samples you might see a comma after the last item in the list. It’s not mandatory, but perfectly valid.

Typically, a list will contain items of a single item type, but it is also possible to include several different types. Lists can also be nested within other lists.

```py
number = 3
things = ["string",  0,  [1,  2, number],  4.56]
print(things[1])
print(things[2])
print(things[2][2])
```

Nested lists can be used to represent 2D grids, such as matrices. For example:

```py
m = [[0,1,2],[4,5,6]]
print(list([1][2])
```


A matrix-like structure can be used in cases where you need to store data in row-column format. For example, when creating a ticketing program, the seat numbers can be stored in a matrix, with their corresponding rows and numbers. 
> The code above outputs the 3rd item of the 2nd row.

Some types, such as strings, can be indexed like lists. Indexing strings behaves as though you are indexing a list containing each character in the string.

For example:

```py
string = "Hello world"
print(string[6])
``` 

Space (” “) is also a symbol and has an index.

> Trying to access a non existing index will lead to an error.

## List Operations

The item at a certain index in a list can be reassigned. For example:

```py
list = [0,1,2,3,4]
list[2] = 5
print(list)
```

> You can replace the item with an item of a different type.

Lists can be added and multiplied in the same way as strings. For example:

```py
nums = [0,1,2]
print(nums + [3,4,5])
print(nums*3)
```

Lists and strings are similar in many ways - strings can be thought of as lists of characters that can’t be changed.

> For example, the string “Hello” can be thought of as a list, where each character is an item in the list. The first item is “H”, the second item is “e”, and so on.

To check if an item is in a list, the in operator can be used. It returns True if the item occurs one or more times in the list, and False if it doesn’t.

```py
words = ["spam",  "egg",  "spam",  "sausage"]
print("spam"  in words)
print("egg"  in words)
print("tomato"  in words)
```

> The in operator is also used to determine whether or not a string is a substring of another string.

To check if an item is not in a list, you can use the not operator in one of the following ways:

```py
nums = [1,  2,  3]
print(not  4  in nums)
print(4  not  in nums)
print(not  3  in nums)
print(3  not  in nums)
```

## List Functions

The append method adds an item to the end of an existing list. For example:

```py
nums = [1,2,3]
nums.append[4]
print(nums)
```

> The dot before append is there because it is a method of the list class. Methods will be explained in later.

To get the number of items in a list, you can use the len function.

```py
list = [0,1,2,3,4]
print(len(list))
```

Unlike the index of the items, len does not start with 0. So, the list above contains 5 items, meaning len will return 5.

> `len` is written before the list it is being called on, without a dot.

The insert method is similar to append, except that it allows you to insert a new item at any position in the list, as opposed to just at the end.

```py
words = ["Python",  "fun"]
index = 1
words.insert(index,  "is")
print(words)
```

> Elements, that are after the inserted item, are shifted to the right.

The index method finds the first occurrence of a list item and returns its index. If the item isn’t in the list, it raises a ValueError.

```py
letters = ['p',  'q',  'r',  's',  'p',  'u']
print(letters.index('r'))
print(letters.index('p'))
print(letters.index('z'))
```

There are a few more useful functions and methods for lists.

`max(list)`: Returns the list item with the maximum value

`min(list)`: Returns the list item with minimum value

`list.count(item)`: Returns a count of how many times an item occurs in a list.

`list.remove(item)`: Removes an object from a list

`list.reverse()`: Reverses items in a list.

> For example, you can count how many 42s are there in the list using: items.count(42) where items is the name of our list.

## While Loops

A while loop is used to repeat a block of code multiple times. For example, let’s say we need to process multiple user inputs, so that each time the user inputs something, the same block of code needs to execute.

Below is a while loop containing a variable that counts up from 1 to 5, at which point the loop terminates.

```py
i = 1
while i <=5:
    print(i)
    i += 1
print("Finished!")
```

During each loop iteration, the i variable will get incremented by one, until it reaches 5. So, the loop will execute the print statement 5 times.

> The code in the body of a while loop is executed repeatedly. This is called iteration.

You can use multiple statements in the while loop.

For example, you can use an if statement to make decisions. This can be useful, if you are making a game and need to loop through a number of player actions and add or remove points of the player.

The code below uses an if/else statement inside a while loop to separate the even and odd numbers in the range of 1 to 10:

```py
x = 1
while x <= 10:
    if x%2 == 0:
        print(str(x) + "is even")
    else:
        print(str(x) + "is odd")
    x += 1
```

`str(x)` is used to convert the number x to a string, so that it can be used for concatenation.

> In console, you can stop the program’s execution by using the Ctrl-C shortcut or by closing the program.

`break`

To end a while loop prematurely, the break statement can be used. For example, we can break an infinite loop if some condition is met:

```py
i = 0
while  1==1:
    print(i)
    i = i + 1
    if i >= 5:
        print("Breaking")
        break
print("Finished")
```

while True is a short and easy way to make an infinite loop.

An example use case of break: An infinite while loop can be used to continuously take user input. For example, you are making a calculator and need to take numbers from the user to add and stop, when the user enters “stop”. In this case, the break statement can be used to end the infinite loop when the user input equals “stop”.

> Using the break statement outside of a loop causes an error.

`continue`

Another statement that can be used within loops is continue. Unlike break, continue jumps back to the top of the loop, rather than stopping it. Basically, the continue statement stops the current iteration and continues with the next one.

For example:

```py
i = 0
while i<5:
    i += 1
    if i==3:
        print("Skipping 3")
        continue
    print(i)
```

An example use case of continue: An airline ticketing system needs to calculate the total cost for all tickets purchased. The tickets for children under the age of 1 are free. We can use a while loop to iterate through the list of passengers and calculate the total cost of their tickets. Here, the continue statement can be used to skip the children.

> Using the continue statement outside of a loop causes an error.

## for Loop

The for loop is used to iterate over a given sequence, such as lists or strings.

The code below outputs each item in the list and adds an exclamation mark at the end:

```py
words = ['hello', 'world']
for word in words:
    print(word + '!')
```

> In the code above, the word variable represents the corresponding item of the list in each iteration of the loop. During the 1st iteration, word is equal to “hello”, and during the 2nd iteration it’s equal to “world”.

The for loop can be used to iterate over strings.

For example:

```py
str = "testing for loops"
count = 0
for x in  str:
    if(x == 't'):
        count += 1
print(count)
```

The code above defines a count variable, iterates over the string and calculates the count of ‘t’ letters in it. During each iteration, the x variable represents the current letter of the string. The count variable is incremented each time the letter ‘t’ is found, thus, at the end of the loop it represents the number of ‘t’ letters in the string. >Similar to while loops, the break and continue statements can be used in for loops, to stop the loop or jump to the next iteration.
for vs while

Both, for and while loops can be used to execute a block of code for multiple times.

It is common to use the for loop when the number of iterations is fixed. For example, iterating over a fixed list of items in a shopping list.

The while loop is used in cases when the number of iterations is not known and depends on some calculations and conditions in the code block of the loop. For example, ending the loop when the user enters a specific input in a calculator program.

> Both, for and while loops can be used to achieve the same results, however, the for loop has cleaner and shorter syntax, making it a better choice in most cases.

### Range

The `range()` function returns a sequence of numbers. By default, it starts from 0, increments by 1 and stops before the specified number.

The code below generates a list containing all of the integers, up to 10.

```py
nums = list(range(10))
print(nums)
```

> In order to output the range as a list, we need to explicitly convert it to a list, using the list() function.

If range is called with one argument, it produces an object with values from 0 to that argument. If it is called with two arguments, it produces values from the first to the second. For example:

```py
nums = list(range(3,10))
print(numbers)

print(range(20) == range(0, 20))
```

> Remember, the second argument is not included in the range, so range(3, 8) will not include the number 8.

range can have a third argument, which determines the interval of the sequence produced, also called the step.

```py
numbers = list(range(5,20,2))
print(numbers)
```
    
> We can also create list of decreasing numbers, using a negative number as the third argument, for example list(range(20, 5, -2)).

## for Loops

The for loop is commonly used to repeat some code a certain number of times. This is done by combining for loops with range objects.

```py
for i in range(5):
    print("hello world!")
```

> You don’t need to call list on the range object when it is used in a for loop, because it isn’t being indexed, so a list isn’t required.

## Functions

You’ve already used functions previously. Any statement that consists of a word followed by information in parentheses is a function call. Here are some examples that you’ve already seen:

```py
print("Hello world")
range(2,20)
str(12)
range(10,20,3)
```


> The words in front of the parentheses are function names, and the comma-separated values inside the parentheses are function arguments.

In addition to using pre-defined functions, you can create your own functions by using the def statement. Here is an example of a function named my_func. It takes no arguments, and prints “spam” three times. It is defined, and then called. The statements in the function are executed only when the function is called.

```py
def my_func():
    print("spam")
    print("spam")
    print("spam")
my_func()
```

> The code block within every function starts with a colon (:) and is indented.

You must define functions before they are called, in the same way that you must assign variables before using them.

```py
hello()

def hello():
    print('Hello world')
```

### Arguments

All the function definitions we’ve looked at so far have been functions of zero arguments, which are called with empty parentheses. However, most functions take arguments. The example below defines a function that takes one argument:

```py
def print_with_exclamation(word):
    print(word + "!")
print_with_exclamation("spam")
print_with_exclamation("eggs")
print_with_exclamation("python")
```
    
> As you can see, the argument is defined inside the parentheses.

You can also define functions with more than one argument; separate them with commas.

```py
def print_sum_twice(x, y):
    print(x+y)
    print(x+y)

print_sum_twice(5, 20)
```

Function arguments can be used as variables inside the function definition. However, they cannot be referenced outside of the function’s definition. This also applies to other variables created inside a function.

```py
def function(variable):
    variable += 1
    print(variable)
function(7)
print(variable)
```

This code will throw an error because the variable is defined inside the function and can be referenced only there. >Technically, parameters are the variables in a function definition, and arguments are the values put into parameters when functions are called.
Returning from Functions

Certain functions, such as int or str, return a value that can be used later. To do this for your defined functions, you can use the return statement.

For example:

```py
def  max(x, y):
    if x >=y:
        return x
    else:
        return y
print(max(4,  7))
z = max(8,  5)
print(z)
```
    
> The return statement cannot be used outside of a function definition.

Once you return a value from a function, it immediately stops being executed. Any code after the return statement will never happen. For example:

```py
def add_numbers(x, y):
    total = x + y
    return total
    print("This won't be printed")
print(add_numbers(4,  5))
```

Although they are created differently from normal variables, functions are just like any other kind of value. They can be assigned and reassigned to variables, and later referenced by those names.

```py
def multiply(x, y):
    return x * y
a = 4
b = 7
operation = multiply
print(operation(a, b))
```
    
> The example above assigned the function multiply to a variable operation. Now, the name operation can also be used to call the function.

Functions can also be used as arguments of other functions.

```py
def add(x, y):
    return x + y
def do_twice(func, x, y):
return func(func(x, y), func(x, y))
a = 5
b = 10
print(do_twice(add, a, b))
```

## Modules

Modules are pieces of code that other people have written to fulfill common tasks, such as generating random numbers, performing mathematical operations, etc.

The basic way to use a module is to add import module_name at the top of your code, and then using module_name.var to access functions and values with the name var in the module. For example, the following example uses the random module to generate random numbers:

```py
import random
for i in  range(5):
    value = random.randint(1,  6)
    print(value)
```
> The code uses the randint function defined in the random module to print 5 random numbers in the range 1 to 6.

There is another kind of import that can be used if you only need certain functions from a module. These take the form from module_name import var, and then var can be used as if it were defined normally in your code. For example, to import only the pi constant from the math module:

```py
from math import pi
    print(pi)
```
Use a comma separated list to import multiple objects. For example:

```py
from math import pi, sqrt
print(sqrt(pi))
```
> `*` imports all objects from a module. For example: from math import *. This is generally discouraged, as it confuses variables in your code with variables in the external module.

## The standard library

There are three main types of modules in Python, those you write yourself, those you install from external sources, and those that are preinstalled with Python. The last type is called the standard library, and contains many useful modules. Some of the standard library’s useful modules include string, re, datetime, math, random, os, multiprocessing, subprocess, socket, email, json, doctest, unittest, pdb, argparse and sys.

Tasks that can be done by the standard library include string parsing, data serialization, testing, debugging and manipulating dates, emails, command line arguments, and much more!


Some of the modules in the standard library are written in Python, and some are written in C. Most are available on all platforms, but some are Windows or Unix specific.

Many third-party Python modules are stored on the Python Package Index (PyPI). The best way to install these is using a program called pip. This comes installed by default with modern distributions of Python. If you don’t have it, it is easy to install online. Once you have it, installing libraries from PyPI is easy. Look up the name of the library you want to install, go to the command line (for Windows it will be the Command Prompt), and enter pip install library_name. Once you’ve done this, import the library and use it in your code.

Using pip is the standard way of installing libraries on most operating systems, but some libraries have prebuilt binaries for Windows. These are normal executable files that let you install libraries with a GUI the same way you would install other programs.

## Files

You can use Python to read and write the contents of files. Text files are the easiest to manipulate. Before a file can be edited, it must be opened, using the open function.

```py
myfile = open("filename.txt")

```
> The argument of the open function is the path to the file. If the file is in the current working directory of the program, you can specify only its name.

You can specify the mode used to open a file by applying a second argument to the open function. Sending “r” means open in read mode, which is the default. Sending “w” means write mode, for rewriting the contents of a file. Sending “a” means append mode, for adding new content to the end of the file.

Adding “b” to a mode opens it in binary mode, which is used for non-text files (such as image and sound files). For example:

```py
# write mode
open("filename.txt", "w")

# read mode
open("filename.txt", "r")
open("filename.txt")

# binary write mode
open("filename.txt", "wb")
```

> You can use the + sign with each of the modes above to give them extra access to files. For example, r+ opens the file for both reading and writing.

Once a file has been opened and used, you should close it. This is done with the close method of the file object.

```py
file = open("filename.txt", "w")
# do stuff to the file
file.close()
```

The contents of a file that has been opened in text mode can be read using the read method.

```py
file = open("filename.txt", "r")
cont = file.read()
print(cont)
file.close()
```

This will print all of the contents of the file “filename.txt”.

To read only a certain amount of a file, you can provide a number as an argument to the read function. This determines the number of bytes that should be read. You can make more calls to read on the same file object to read more of the file byte by byte. With no argument, read returns the rest of the file.

```py
file = open("filename.txt", "r")
print(file.read(16))
print(file.read(4))
print(file.read(4))
print(file.read())
file.close()
```

> Just like passing no arguments, negative values will return the entire contents.

After all contents in a file have been read, any attempts to read further from that file will return an empty string, because you are trying to read from the end of the file.

```py
file = open("filename.txt", "r")
file.read()
print("Re-reading")
print(file.read())
print("Finished")
file.close()
```

Result:

```
>>>
Re-reading

Finished
>>>
```

To retrieve each line in a file, you can use the readlines method to return a list in which each element is a line in the file. For example:

file = open(“filename.txt”, “r”) print(file.readlines()) file.close()

Result:

```
>>>
['Line 1 text \n', 'Line 2 text \n', 'Line 3 text']
>>>
```

You can also use a for loop to iterate through the lines in the file:

```py
file = open("filename.txt", "r")

for line in file:
print(line)

file.close()
```

Result:

```py
>>>
Line 1 text

Line 2 text

Line 3 text
>>>
```

In the output, the lines are separated by blank lines, as the print function automatically adds a new line at the end of its output.

To write to files you use the write method, which writes a string to the file. For example:

```py
file = open("newfile.txt",  "w")
file.write("This has been written to a file")
file.close()
file = open("newfile.txt",  "r")
print(file.read())
file.close()
```

> The “w” mode will create a file, if it does not already exist.

When a file is opened in write mode, the file’s existing content is deleted.

```py
file = open("newfile.txt",  "w")
file.write("Some new text")
file.close()
file = open("newfile.txt",  "r")
print("Reading new contents")
print(file.read())
print("Finished")
file.close()
```

> As you can see, the content of the file has been overwritten.

The write method returns the number of bytes written to a file, if successful.

```py
msg = "Hello world!"
file = open("newfile.txt",  "w")
amount_written = file.write(msg)
print(amount_written)
file.close()
```

To write something other than a string, it needs to be converted to a string first.

It is good practice to avoid wasting resources by making sure that files are always closed after they have been used.

A way of doing this is using with statements. This creates a temporary variable (often called f), which is only accessible in the indented block of the with statement.

```py
with open("filename.txt")  as f:
    print(f.read())
```

> The file is automatically closed at the end of the with statement, even if exceptions occur within it.


## None

The **None** object is used to represent the absence of a value. It is similar to null in other programming languages. Like other “empty” values, such as 0, [] and the empty string, it is False when converted to a Boolean variable. When entered at the Python console, it is displayed as the empty string.

```py
print(None)
```

> Run the code and see how it works!

The None object is returned by any function that doesn’t explicitly return anything else.

```py
def some_func():
print("Hi!")
var = some_func()
print(var)
```

## Dictionaries

Dictionaries are data structures used to map arbitrary keys to values. Lists can be thought of as dictionaries with integer keys within a certain range. Dictionaries can be indexed in the same way as lists, using square brackets containing keys. Example:

```py
ages = {"Dave":  24,  "Mary":  42,  "John":  58}
print(ages["Dave"])
print(ages["Mary"])
```

> Each element in a dictionary is represented by a key:value pair.

Trying to index a key that isn’t part of the dictionary returns a KeyError. Example:

```py
primary = {
"red":  [255,  0,  0],
"green":  [0,  255,  0],
"blue":  [0,  0,  255],
}
print(primary["red"])
print(primary["yellow"])
```

As you can see, a dictionary can store any types of data as values. >An empty dictionary is defined as {}.

Only immutable objects can be used as keys to dictionaries. Immutable objects are those that can’t be changed. So far, the only mutable objects you’ve come across are lists and dictionaries. Trying to use a mutable object as a dictionary key causes a TypeError.

```py
bad_dict = {

[1,  2,  3]:  "one two three",

}
```

> Run the code and see how it works!

Just like lists, dictionary keys can be assigned to different values. However, unlike lists, a new dictionary key can also be assigned a value, not just ones that already exist.

```py
squares = {1:  1,  2:  4,  3:  "error",  4:  16,}
squares[8] = 64
squares[3] = 9
print(squares)
```

To determine whether a key is in a dictionary, you can use in and not in, just as you can for a list. Example:

```py
nums = {
1:  "one",
2:  "two",
3:  "three",
}
print(1  in nums)
print("three"  in nums)
print(4  not  in nums)
```

A useful dictionary method is get. It does the same thing as indexing, but if the key is not found in the dictionary it returns another specified value instead (‘None’, by default). Example:

```py
pairs = {1:  "apple",
"orange":  [2,  3,  4],
True:  False,
None:  "True",
}

print(pairs.get("orange"))
print(pairs.get(7))
print(pairs.get(12345,  "not in dictionary"))
```

## Tuples

Tuples are very similar to lists, except that they are immutable (they cannot be changed). Also, they are created using parentheses, rather than square brackets. Example:

`words = ("spam", "eggs", "sausages",)`

You can access the values in the tuple with their index, just as you did with lists:

`print(words[0])`

Trying to reassign a value causes a TypeError.

`words[1] = "cheese"`

> You can access the values in the tuple with their index, just as you did with lists.

Tuples can be created without the parentheses, by just separating the values with commas. Example:

```py
my_tuple = "one", "two", "three"
print(my_tuple[0])
```

An empty tuple is created using an empty parenthesis pair.

`tpl = ()`

> Tuples are faster than lists, but they cannot be changed.

## List Slices

List slices provide a more advanced way of retrieving values from a list. Basic list slicing involves indexing a list with two colon-separated integers. This returns a new list containing all the values in the old list between the indices. Example:

```py
squares = [0,  1,  4,  9,  16,  25,  36,  49,  64,  81]
print(squares[2:6])
print(squares[3:8])
print(squares[0:1])
```

> Like the arguments to range, the first index provided in a slice is included in the result, but the second isn’t.

If the first number in a slice is omitted, it is taken to be the start of the list. If the second number is omitted, it is taken to be the end. Example:

```py
squares = [0,  1,  4,  9,  16,  25,  36,  49,  64,  81]
print(squares[:7])
print(squares[7:])
```

> Slicing can also be done on tuples.

List slices can also have a third number, representing the step, to include only alternate values in the slice.

```py
squares = [0,  1,  4,  9,  16,  25,  36,  49,  64,  81]
print(squares[::2])
print(squares[2:8:3])
```

> [2:8:3] will include elements starting from the 2nd index up to the 8th with a step of 3.

Negative values can be used in list slicing (and normal list indexing). When negative values are used for the first and second values in a slice (or a normal index), they count from the end of the list.

```py
squares = [0,  1,  4,  9,  16,  25,  36,  49,  64,  81]
print(squares[1::-1])
```

> If a negative value is used for the step, the slice is done backwards. Using [::-1] as a slice is a common and idiomatic way to reverse a list.

## List Comprehensions

List comprehensions are a useful way of quickly creating lists whose contents obey a simple rule. For example, we can do the following:

```py
# a list comprehension
cubes = [i**3  for i in  range(5)]
print(cubes)
```

> List comprehensions are inspired by set-builder notation in mathematics.

A list comprehension can also contain an if statement to enforce a condition on values in the list. Example:

```py
evens=[i**2  for i in  range(10)  if i**2 % 2 == 0]
print(evens)
```

Trying to create a list in a very extensive range will result in a MemoryError. This code shows an example where the list comprehension runs out of memory.

```py
even = [2*i for i in  range(10**100)]
```

> This issue is solved by generators, which are covered later.

## String Formatting

So far, to combine strings and non-strings, you’ve converted the non-strings to strings and added them. String formatting provides a more powerful way to embed non-strings within strings. String formatting uses a string’s format method to substitute a number of arguments in the string. Example:

```py
# string formatting
nums = [4,  5,  6]
msg = "Numbers: {0} {1} {2}". format(nums[0], nums[1], nums[2])
print(msg)
```

> Each argument of the format function is placed in the string at the corresponding position, which is determined using the curly braces { }.

String formatting can also be done with named arguments. Example:

```py
a= "{x}, {y}".format(x = 5, y = 12)
print(a)
```

## String Functions

Python contains many useful built-in functions and methods to accomplish common tasks. join - joins a list of strings with another string as a separator. replace - replaces one substring in a string with another. startswith and endswith - determine if there is a substring at the start and end of a string, respectively. To change the case of a string, you can use lower and upper. The method split is the opposite of join turning a string with a certain separator into a list. Some examples:

```py
print(", ".join(["spam",  "eggs",  "ham"]))
#prints "spam, eggs, ham"

print("Hello ME".replace("ME",  "world"))
#prints "Hello world"

print("This is a sentence.".startswith("This"))
# prints "True"

print("This is a sentence.".endswith("sentence."))
# prints "True"

print("This is a sentence.".upper())
# prints "THIS IS A SENTENCE."

print("AN ALL CAPS SENTENCE".lower())
#prints "an all caps sentence"

print("spam, eggs, ham".split(", "))
#prints "['spam', 'eggs', 'ham']"
```

## Numeric Functions

To find the maximum or minimum of some numbers or a list, you can use max or min. To find the distance of a number from zero (its absolute value), use abs. To round a number to a certain number of decimal places, use round. To find the total of a list, use sum. Some examples:

```py
print(min(1,  2,  3,  4,  0,  2,  1))
print(max([1,  4,  9,  2,  5,  6,  8]))
print(abs(-99))
print(abs(42))
print(sum([1,  2,  3,  4,  5]))
```

## List Functions

Often used in conditional statements, all and any take a list as an argument, and return True if all or any (respectively) of their arguments evaluate to True (and False otherwise). The function enumerate can be used to iterate through the values and indices of a list simultaneously. Example:

```py
nums = [55,  44,  33,  22,  11]
if  all([i > 5  for i in nums]):
    print("All larger than 5")

if  any([i % 2 == 0  for i in nums]):
    print("At least one is even")

for v in  enumerate(nums):
    print(v)
```


## Lambdas

Creating a function normally (using def) assigns it to a variable automatically. This is different from the creation of other objects - such as strings and integers - which can be created on the fly, without assigning them to a variable. The same is possible with functions, provided that they are created using lambda syntax. Functions created this way are known as anonymous. This approach is most commonly used when passing a simple function as an argument to another function. The syntax is shown in the next example and consists of the lambda keyword followed by a list of arguments, a colon, and the expression to evaluate and return.

```py
def my_func(f, arg):
return f(arg)

my_func(lambda x: 2*x*x, 5)
```

> Lambda functions get their name from lambda calculus, which is a model of computation invented by Alonzo Church.

Lambda functions aren’t as powerful as named functions. They can only do things that require a single expression - usually equivalent to a single line of code. Example:

```py
#named function
def polynomial(x):
return x**2 + 5*x + 4
print(polynomial(-4))

#lambda
print((lambda x: x**2 + 5*x + 4)  (-4))
```

> In the code above, we created an anonymous function on the fly and called it with an argument.

Lambda functions can be assigned to variables, and used like normal functions. Example:

```py
double = lambda x: x * 2
print(double(7))
```

> However, there is rarely a good reason to do this - it is usually better to define a function with def instead.

## map

The function map takes a function and an iterable as arguments, and returns a new iterable with the function applied to each argument. Example:

```py
def add_five(x):
return x + 5

nums = [11,  22,  33,  44,  55]
result = list(map(add_five, nums))
print(result)
```

We could have achieved the same result more easily by using lambda syntax.

```py
nums = [11,  22,  33,  44,  55]

result = list(map(lambda x: x+5, nums))
print(result)
```

## filter

The function filter filters an iterable by removing items that don’t match a predicate (a function that returns a Boolean). Example:

```py
nums = [11,  22,  33,  44,  55]
res = list(filter(lambda x: x%2==0, nums))
print(res)
```

> Like map, the result has to be explicitly converted to a list if you want to print it.

## Generators

Generators are a type of iterable, like lists or tuples. Unlike lists, they don’t allow indexing with arbitrary indices, but they can still be iterated through with for loops. They can be created using functions and the yield statement. Example:

```py
def countdown():
    i=5
    while i > 0:
        yield i
        i -= 1
for i in countdown():
    print(i)
```

> The yield statement is used to define a generator, replacing the return of a function to provide a result to its caller without destroying local variables.

Due to the fact that they yield one item at a time, generators don’t have the memory restrictions of lists. In fact, they can be infinite!

```py
def infinite_sevens():
    while True:
        yield 7

for i in infinite_sevens():
    print(i)
```

Result:

```
>>>
7
7
7
7
7
7
7
...
```

> In short, generators allow you to declare a function that behaves like an iterator, i.e. it can be used in a for loop.

Finite generators can be converted into lists by passing them as arguments to the list function.

```py
def numbers(x):
    for i in  range(x):
        if i % 2 == 0:
            yield i
print(list(numbers(11)))
```
    
> Using generators results in improved performance, which is the result of the lazy (on demand) generation of values, which translates to lower memory usage. Furthermore, we do not need to wait until all the elements have been generated before we start to use them.

## Sets

Sets are data structures, similar to lists or dictionaries. They are created using curly braces, or the set function. They share some functionality with lists, such as the use of in to check whether they contain a particular item.

```py
num_set = {1,  2,  3,  4,  5}
word_set = set(["spam",  "eggs",  "sausage"])

print(3  in num_set)
print("spam"  not  in word_set)
```

> To create an empty set, you must use `set()`, as `{}` creates an empty dictionary.

Sets differ from lists in several ways, but share several list operations such as len. They are unordered, which means that they can’t be indexed. They cannot contain duplicate elements. Due to the way they’re stored, it’s faster to check whether an item is part of a set, rather than part of a list. Instead of using append to add to a set, use add. The method remove removes a specific element from a set; pop removes an arbitrary element.

```py
nums = {1,  2,  1,  3,  1,  4,  5,  6}
print(nums)
nums.add(-7)
nums.remove(3)
print(nums)
```
    
> Basic uses of sets include membership testing and the elimination of duplicate entries.

Sets can be combined using mathematical operations. The union operator `|` combines two sets to form a new one containing items in either. The intersection operator `&` gets items only in both. The difference operator `-` gets items in the first set but not in the second. The symmetric difference operator `^` gets items in either set, but not both.

```py
first = {1,  2,  3,  4,  5,  6}
second = {4,  5,  6,  7,  8,  9}

print(first | second)
print(first & second)
print(first - second)
print(second - first)
print(first ^ second)
```


{{ webring(webring="#", webringName="Go to the Top") }}
