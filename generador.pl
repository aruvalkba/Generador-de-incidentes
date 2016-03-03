#!/usr/bin/perl

use strict;
#use warnings;

use Getopt::Long qw(GetOptions);	
use Pod::Usage;
use Data::Dumper;
use Linux::Inotify2;
use SnortUnified(qw(:ALL));
use Socket;

	#variables para las opciones del programa
    my ($help,$cont,$dir,$org,$log);
    my @batch;
    my ($dir_set, $dir_value, $ori_get, $ori_value);
    my $filetest;
    #se obtienen las opciones de la linea de comandos
    GetOptions(
        'help|h' 			=> 	\$help,
        'batch|b=s' 		=> 	\@batch,
        'continious|c' 		=> 	\$cont,
        'directory|d=s' 	=>	\&dir,
        'origin|o=s'		=>	\&org,
        'log|l=s'			=>	\$log,

    )or die "Modo de uso: perl generador.pl [-h|--help] [-b|--batch logfile1..] [-c|--continious] [-d|--directory path] [-o|--origin path] [-l|--log path]\n";
    

    #if($dir){
    #    say $dir;
    #}
    #si se selecciona la opcion -h o --help se muestra la documentacion definida al final de este archivo
    pod2usage(-verbose => 2) if ($help);
     
    
    #if(@batch){
    #    batch();
    #}
    
    my $inotify = new Linux::Inotify2;
    $dir = "archivos";
    opendir(DIR, $dir);
    while(readdir DIR){
        -d $_ and $inotify->watch($_, IN_CREATE, \&handle_new);
    }

    sub batch {

    }


    sub continious {
        

    }

    sub watch_new {
        my $e = shift;
        my $filecont = "continuo";
        open(my $danfile, ">>", $filecont) or die "No se pudo crear el archivo";
        print $danfile "New file or dir: " . $e->fullname . "\n";
        close($danfile);
    }

    sub dir {
        my ($dir_set, $dir_value) = @_;
        print $dir_value . "\n";
        mkdir $dir_value, 0777;
    }


    sub org {
        my ($ori_get, $ori_value) = @_;
        opendir(DIR, $ori_value) or die "Error no se puede abrir el directorio $ori_get";
        while(( $filetest = readdir(DIR))){
            if($filetest =~ /(.*log.*)/){
                
                my $cont = 0;
                my $record; #variable para cada evento IDS y paquete del archivo
                my $rutarchivo = "./$ori_value/$filetest";
                print $rutarchivo;
                my $UF_DATA = openSnortUnified($rutarchivo); #se lee el archivo de snort
                my @arrayfile;
                my $filename = 'unified2procesado';
                my $filenam2 = 'archivotextoclaro';
                open(my $danfile, '>',$filename) or die "No se abrio el archivo '$filename' $!";
                binmode($danfile);
                #print $dir_set;
                #se muestra en pantalla el contenido del archivo
                while($record = readSnortUnified2Record()){
                    #my $prueba = inet_ntoa $record->{'sip'};
                    #print $prueba;
                    #print "hola";
                    
                    if($record->{'TYPE'} == 7){
                    #   my $new2 = pack('N11n2c2',$record);
                        #print "Evento: \n";
                        #print $record->{'TYPE'} . "\n";
                        #print $record->{'SIZE'} . "\n";
                        my $typesize = pack('NN',$record->{'TYPE'},$record->{'SIZE'});
                        my $sensorid = pack('N',$record->{'sensor_id'});
                        my $eventid = pack('N',$record->{'event_id'});
                        my $tvsec = pack('N',$record->{'tv_sec'});
                        my $tvusec = pack('N',$record->{'tv_usec'});
                        my $sigid = pack('N',$record->{'sig_id'});
                        my $siggen = pack('N',$record->{'sig_gen'});
                        my $sigrev = pack('N',$record->{'sig_rev'});
                        my $class = pack('N',$record->{'class'});
                        my $pri = pack('N',$record->{'pri'});
                        my $sip = pack('N',$record->{'sip'});
                        my $dip = pack('N',$record->{'dip'});
                        my $sp = pack('n',$record->{'sp'});
                        my $dp = pack('n',$record->{'dp'});
                        my $protocol = pack('c',$record->{'protocol'});
                        my $impactflag = pack('c',$record->{'impact_flag'});
                        my $impact = pack('c',$record->{'impact'});
                        my $blocked = pack('c',$record->{'blocked'});

                        

                        print $danfile $typesize;
                        print $danfile $sensorid;
                        print $danfile $eventid;
                        print $danfile $tvsec;
                        print $danfile $tvusec;
                        print $danfile $sigid;
                        print $danfile $siggen;
                        print $danfile $sigrev;
                        print $danfile $class;
                        print $danfile $pri;
                        print $danfile $sip;
                        print $danfile $dip;
                        print $danfile $sp;
                        print $danfile $dp;
                        print $danfile $protocol;
                        print $danfile $impactflag;
                        print $danfile $impact;
                        print $danfile $blocked;
                    }
                    if($record->{'TYPE'} == 2){
                        ##print "Paquete: \n";

                        ##print $record->{'TYPE'} . "\n";
                        ##print $record->{'SIZE'} . "\n";
                        ###print @{$record{'TYPE'}};
                        ##print "Paquete: \'" . pack('b',$record->{'pkt'}) . "\'\n";
                        ##print "Paquete: \'" . $record->{'pkt'} . "\'\n";
                        my $headerpaquete = pack('N10',$record->{'TYPE'},$record->{'SIZE'}, $record->{'sensor_id'}, $record->{'event_id'}, $record->{'tv_sec'}, $record->{'pkt_sec'}, $record->{'pkt_usec'}, $record->{'linktype'}, $record->{'pkt_len'}, $record->{'raw_record'});
                        
                        #my $typesize = pack('NN',$record->{'TYPE'},$record->{'SIZE'});
                        #my $asensorid = pack('N', $record->{'sensor_id'});
                        #my $aeventid = pack('N', $record->{'event_id'});
                        #my $aseg = pack('N', $record->{'tv_sec'});
                        #my $apaquetesec = pack('N', $record->{'pkt_sec'});
                        #my $apaqueteusec = pack('N', $record->{'pkt_usec'});
                        #my $alntype = pack('N', $record->{'linktype'});
                        #my $apaquetelen = pack('N', 0);
                        #my $apaquete = pack('N', 0);
                        

                        #print $danfile $typesize;
                        #print $danfile $asensorid;
                        #print $danfile $aeventid;
                        #print $danfile $aseg;
                        #print $danfile $apaquetesec;
                        #print $danfile $apaqueteusec;
                        #print $danfile $alntype;
                        #print $danfile $apaquetelen;
                        ##print $danfile $apaquete;

                    print $danfile $headerpaquete;
                }
        
        
                #print Dumper($record);
        

                }
                close $danfile;
                closeSnortUnified();            
            }
        }
        closedir(DIR);
    }


    sub log {

    }
	
#print "hola";

#print $cont;

#foreach(@arrayfile){
#    print unpack('N',$_);
#}    

sub make_hex() {
		my $data = shift;
		return unpack("h* ",$data);
}

sub make_ascii() {
		my $data = shift;
		print $data;
		my $asc = unpack('a*', $data);
		$asc =~ tr/A-Za-z0-9;:\"\'.,<>[]\\|?\/\`~!\@#$%^&*()_\-+={}/./c;
		return $asc;
}

__END__
    
=head1 NOMBRE

    Generador de incidentes - obtiene el primer y ultimo evento de archivos unified2

=head1 SINOPSIS

    perl generador.pl [opciones] [archivo ...]
    
=head1 DESCRIPCION

    Este programa recibe como entrada uno o varios archivos unified2 
    para procesarlos y genera un nuevo archivo unifed2 que contendra 
    unicamente el primer y ultimo evento de un incidente de forma que
    se reduzca significativamente el tamano de cada archivo generado.
    Ademas genera un archivo en texto plano donde se almacenan el 
    numero de eventos por incidente. 


=head1 OPCIONES

=head2  -h, --help

    Muestra la ayuda del programa        
    
=head2  -b, --batch 

    Modo por lotes: procesa uno o varios archivos para obtener los 
    incidentes.

=head2 -c- --continious

    El programa se ejecuta como un demonio del sistema y revisa de manera
    cotinua el directorio en busca de nuevos eventos en el archivo.


=head2 -d, --directory

    Directorio en el cual se guardan los archivos generados

=head2 -o, --origin

    Directorio que contiene los archivos unified2 a procesar

=head2 -l, --log 
    
    Directorio que contiene las bitacoras de la ejecucion de la herramienta    

=cut
