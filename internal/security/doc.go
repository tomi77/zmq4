// Package security holds ZMTP 3.1 security mechanism state machines.
//
// Each mechanism (NULL, PLAIN, CURVE) lives in its own subpackage and
// implements a pure, I/O-free state machine consumed by the connection
// layer (F4). No package in security/ depends on net, time, or
// goroutines.
package security
