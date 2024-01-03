package stack

import "errors"

var EmptyStack = errors.New("stack is empty")

type Stack[T any] []T

func (st Stack[T]) IsEmpty() bool {
	return len(st) <= 0
}

func (st Stack[T]) Len() uint {
	return uint(len(st))
}

func (st Stack[T]) Peek() T {
	if st.IsEmpty() {
		panic(EmptyStack)
	}
	n := st.Len()
	return st[n-1]
}

func (st *Stack[T]) Push(item T) {
	*st = append(*st, item)
}

func (st *Stack[T]) Pop() T {
	if st.IsEmpty() {
		panic(EmptyStack)
	}
	n := st.Len() - 1
	item := (*st)[n]
	var zero T
	(*st)[n] = zero
	*st = (*st)[:n]
	return item
}
