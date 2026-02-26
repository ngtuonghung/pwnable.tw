int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  char s[136]; // [rsp+0h] [rbp-90h] BYREF
  unsigned __int64 v4; // [rsp+88h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  init_proc(argc, argv, envp);
  memset(s, 0, 0x80uLL);
  printf("Input :");
  close(1);
  read(0, s, 0x80uLL);
  printf(s);
  exit(0);
}