#!/usr/bin/perl
use strict;
use warnings;
use 5.010;
use Getopt::Long qw(GetOptions);
use Data::Dumper;
     
    #variables de prueba para los flags en linea de comandos 
    my $help;
    my @batch;
    my $cont;
    my $dir;
    my $org;
    my $log;
   
    GetOptions(
        'help|h' 			=> 	\$help,
        'batch|b=s' 		=> 	\@batch,
        'continious|c' 		=> 	\$cont,
        'directory|d=s' 	=>	\$dir,
        'origin|o=s'		=>	\$org,
        'log|l=s'			=>	\$log,

    ) or die "Modo de uso: perl generador.pl [-h|--help] [-b|--batch logfile1..] [-c|--continious] [-d|--directory path] [-o|--origin path] [-l|--log path]\n";
     
    
    if ($help) {
        help();
    }
    elsif(@batch){
        batch();
    }
    
	sub help {
	  print "Se muestra la ayuda\n";
	  return;
	}


    sub batch {

    }


    sub continious {

    }



    sub directory {

    }


    sub origin {

    }


    sub log {

    }