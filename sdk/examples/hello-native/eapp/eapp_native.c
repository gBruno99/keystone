//******************************************************************************
// Copyright (c) 2018, The Regents of the University of California (Regents).
// All Rights Reserved. See LICENSE for license details.
//------------------------------------------------------------------------------
#include "eapp_utils.h"
#include "string.h"
#include "edge_call.h"
#include <syscall.h>

#define OCALL_PRINT_STRING 1
#define OCALL_PRINT_NUMBER 2

unsigned long ocall_print_string(char* string);
unsigned long ocall_print_number(int num);
int my_print_string(char* string, int* retval);

int main(){

  int len;
  ocall_print_string("Hello World");
  ocall_print_string("Hello World - 2");
  my_print_string("Test SM syscall", &len);
  ocall_print_number(len);

  EAPP_RETURN(0);
}

unsigned long ocall_print_string(char* string){
  unsigned long retval;
  ocall(OCALL_PRINT_STRING, string, strlen(string)+1, &retval ,sizeof(unsigned long));
  return retval;
}

unsigned long ocall_print_number(int num){
  unsigned long retval;
  ocall(OCALL_PRINT_NUMBER, &num, sizeof(int), &retval ,sizeof(unsigned long));
  return retval;
}

int
my_print_string(char* string, int* retval){
  int ret;
  ret = print_string(string, strlen(string)+1, retval);
  (*retval)--;
  return ret;
}
