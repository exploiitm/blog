+++ title = "FILTERMAZE" date = 2025-08-14 authors = ["Vibhu Mehrotra"] +++

## Summary
The problem has two parts:
1.A maze
2.A mathematical equation, with an error term which hides a secret matrix s

On solving the maze, we get the magnitudes of the error matrix. 
Now, that along with a few mathematical manipulations we can solve for s directly.

## Solution:

- The maze itself can be bruteforced. We can input incomplete paths and check if it is along the correct path. So, we can solve it in O(n^2) , and since the maze has a total of around 20 nodes, its very feasible.


Lets study the second section

Code Explanation
```python
class LWEParams:
  lwe_n: int = 50
  lwe_m: int = 100
  lwe_q: int = 1009
  A: List[int] = field(init=False)
  s: List[int] = field(init=False)
  e: List[int] = field(init=False)
  b: List[int] = field(init=False)
  
  ```
@dataclass class LWEParams:
Defines default parameters for an LWE (Learning With Errors) problem:

- lwe_n: secret vector length (50)

- lwe_m: number of equations (100)

- lwe_q: modulus (1009) 

A, s, e, b: will store the public matrix, secret vector, error vector, and result vector respectively (set later).

- __post_init__ 
After initialization, generates lwe_error_range, a list of random error magnitudes in [0, q), one for each equation.

- load_graph(filepath)
Reads a JSON graph file from disk, converts string keys to integers, and returns it.

- load_flag(filepath)
Reads the first line of a file (the flag), strips newline characters, and returns it.

- create_lwe_instance_with_error(...)
Generates a random LWE instance:

s: random secret vector of length n, randbelow(q): [0,q) range.

A: random **public** matrix of size m × n with entries in [0, q).

e: error vector whose entries are either +mag or -mag from error_mags.

b: computed as (A @ s + e) mod q, the standard LWE equation.
Returns (A, s, e, b) as lists for further use. **(public)**

### How do we solve this?

Bruteforcing of the maze finally gives us the magnitude of e.
we can run it through this function which uses the following math to get the signs:
$$A @ s + e = b mod q$$
$$A @ s - b = e mod q$$
$$e*-1 (A @ s - b) = sign mod q$$


``` python
def find_signs(A, b, mags):
  basis = Matrix(A).augment(Matrix(b).T)
  basis_ = []
  for i, row in enumerate(basis.rows()):
    basis_.append(pow(mags[i], -1, q) * row)


  basis = Matrix(basis_).augment(diagonal_matrix([q] * m)).T
  lattice = basis.BKZ()

  for row in lattice.rows():
    if all(x in [-1, 1] for x in row):
      return row
```

to get the actual error e with signs.
Now we have the actual e value, all we have to do is invert the equation
$$
b= (A @ s + e) mod q
$$
and solve for s 


>note: we solve this by treating the equation to be in the finite field q, this allows us to use simple modular arithmatic properties to invert the equation.
``` python

def recover_secret(A, b, e, q):
  
    A_mod  = Matrix(GF(q), A)
    rhs    = vector(GF(q), (b - e))

    s = A_mod.solve_right(rhs) #solves for s

    return [int(x) % q for x in s]

```
And thats it! its solved. We can call the get_flag function in the puzzle and give them the secret s we discovered. we are then returned the final flag. :)

>Code for writeup sourced from @ibrahim in GCTF discord server



