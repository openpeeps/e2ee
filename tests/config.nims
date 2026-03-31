switch("path", "$projectDir/../src")

{.passC: "-I/usr/local/include".}
{.passL: "-L/usr/local/lib -lmonocypher".}