switch("path", "$projectDir/../src")

when defined(linux):
  {.passC: "-I/usr/local/include".}
  {.passL: "-L/usr/local/lib -lmonocypher".}
else:
  {.passC: "-I/usr/local/include".}
  {.passL: "-L/usr/local/lib -lmonocypher".}
