#!/usr/bin/env python3

import io, sys, os
import re

if __name__ == "__main__":
	expressions = []

	data = [ ]

	with open("expr.txt","rt") as f_in:
		for line in f_in:
			expressions.append(line.strip())

	with open("test.txt","rt")as f_in:
		for line in f_in:
			line = line.strip()

			for expression in expressions:
				try:
					prog = re.compile(expression)

					match = prog.match(line)

					if match:
						print(f"{expression} matched\n>>> {line}")

						groups = match.groupdict()
						keys = groups.keys()

						for key in keys:
							print(f"XXX Group {key} matched : {groups[key]}")
					else:
						print(f"{expression} does not match\n>>> {line}")

				except Exception as err:
					print(f"Expression {expression} failed to compile - {err}")

