using System;
using System.IO;

public class ParseErr
{
  public static void Main(string[] args)
  {
    StreamReader sr = new StreamReader(args[0],System.Text.Encoding.GetEncoding("windows-1250"));
    string line;
    int i,j=0;

    Console.WriteLine("Kód\tPopis");

    while((line= sr.ReadLine()) != null)
    {
      j++;
      i=line.IndexOf("ERR:");
      if(i>=0)
      {
        Console.WriteLine(j+"\t"+line.Substring(i+4));
      
      }
    }

  if (sr != null)sr.Close(); 
  }
}
