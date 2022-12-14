import numpy as np
import sys
from sklearn.metrics import accuracy_score, confusion_matrix
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.preprocessing import MinMaxScaler
import sklearn
from sklearn.neighbors import KNeighborsClassifier
import os
from sklearn.preprocessing import LabelEncoder
import tensorflow as tf
import pickle
from sklearn import preprocessing

prot_type=sys.argv[1]
service=sys.argv[2]
flag=sys.argv[3]
log_in=int(sys.argv[4])
count=int(sys.argv[5])
srv_serr_rate=float(sys.argv[6])
srv_rerr_rate=float(sys.argv[7])
sm_srv_rate=float(sys.argv[8])
diff_srv_rate=float(sys.argv[9])
dst_hst_count=int(sys.argv[10])
dst_hst_ser_count=int(sys.argv[11])
dst_hst_same_srv_count=float(sys.argv[12])
dst_hst_diff_srv_rate=float(sys.argv[13])
dst_hst_same_src_port_rate=float(sys.argv[14])
dst_hst_serr_rate=float(sys.argv[15])
dst_hst_rerr_rate=float(sys.argv[16])




prot_type_map={'tcp':1,'udp':2,'icmp':0}
serv_type_map={'IRC': 0,
 'X11': 1,
 'Z39_50': 2,
 'http_8001': 3,
 'auth': 4,
 'bgp': 5,
 'courier': 6,
 'csnet_ns': 7,
 'ctf': 8,
 'daytime': 9,
 'discard': 10,
 'domain': 11,
 'domain_u': 12,
 'echo': 13,
 'eco_i': 14,
 'ecr_i': 15,
 'efs': 16,
 'exec': 17,
 'finger': 18,
 'ftp': 19,
 'ftp_data': 20,
 'gopher': 21,
 'harvest': 22,
 'hostnames': 23,
 'http': 24,
 'http_2784': 25,
 'http_443': 26,
 'aol': 27,
 'imap4': 28,
 'iso_tsap': 29,
 'klogin': 30,
 'kshell': 31,
 'ldap': 32,
 'link': 33,
 'login': 34,
 'mtp': 35,
 'name': 36,
 'netbios_dgm': 37,
 'netbios_ns': 38,
 'netbios_ssn': 39,
 'netstat': 40,
 'nnsp': 41,
 'nntp': 42,
 'ntp_u': 43,
 'other': 44,
 'pm_dump': 45,
 'pop_2': 46,
 'pop_3': 47,
 'printer': 48,
 'private': 49,
 'red_i': 50,
 'remote_job': 51,
 'rje': 52,
 'shell': 53,
 'smtp': 54,
 'sql_net': 55,
 'ssh': 56,
 'sunrpc': 57,
 'supdup': 58,
 'systat': 59,
 'telnet': 60,
 'tftp_u': 61,
 'tim_i': 62,
 'time': 63,
 'urh_i': 64,
 'urp_i': 65,
 'uucp': 66,
 'uucp_path': 67,
 'vmnet': 68,
 'whois': 69}
flag_type_map={'OTH': 0,
 'REJ': 1,
 'RSTO': 2,
 'RSTOS0': 3,
 'RSTR': 4,
 'S0': 5,
 'S1': 6,
 'S2': 7,
 'S3': 8,
 'SF': 9,
 'SH': 10}
prot_type=prot_type_map.get(prot_type)
service=serv_type_map.get(service)
flag=flag_type_map.get(flag)
l=[]
l.append(prot_type)
l.append(service)
l.append(flag)
l.append(log_in)
l.append(count)
l.append(srv_serr_rate)
l.append(srv_rerr_rate)
l.append(sm_srv_rate)
l.append(diff_srv_rate)
l.append(dst_hst_count)
l.append(dst_hst_ser_count)
l.append(dst_hst_same_srv_count)
l.append(dst_hst_diff_srv_rate)
l.append(dst_hst_same_src_port_rate)
l.append(dst_hst_serr_rate)
l.append(dst_hst_rerr_rate)
l1 = preprocessing.normalize([l])
knn_bin = pickle.load(open('knn_binary_class.sav', 'rb'))
knn_multi = pickle.load(open('knn_multi_class.sav', 'rb'))
randfor_bin = pickle.load(open('random_forest_binary_class.sav', 'rb'))
randfor_multi = pickle.load(open('random_forest_multi_class.sav', 'rb'))
cnn_bin= tf.keras.models.load_model('cnn_binary_class.h5')
cnn_multi= tf.keras.models.load_model('cnn_multi_class.h5')
lstm_bin= tf.keras.models.load_model('lstm_binary_class.h5')
lstm_multi= tf.keras.models.load_model('lstm_multi_class.h5')

#now check the random file and uppdate DL models i.e lstm and cnn 
val_knn=knn_bin.predict(l1)
if(val_knn[0]==0):
    print('KNN algorithm binary class:Normal')
else:
    print('KNN algorithm binary class:Attack')
print('KNN Algorithm multi class:',knn_multi.predict(l1))
val_rnd=randfor_bin.predict(l1)
if(val_rnd[0]==0):
    print('Random Forsest Algorithm Binary class:Normal')
else:
    print('Random Forsest Algorithm Binary class:Attack')
print('Random Forsest Algorithm Multi class:',randfor_multi.predict(l1))
val_cnn=cnn_bin.predict(l1,verbose=0)
tp=[]
for i in val_cnn:
    for j in i:
        tp.append(round(j))
if(tp[0]==1):
    print('CNN Algorithm binary class: Attack')
else:
    print('CNN Algorithm binary class: Normal')
tp_cnn=cnn_multi.predict(l1,verbose=0)
l=[]
for i in tp_cnn:
    for j in i:
        l.append(round(j))
if(l[1]==1):
   print('CNN Algorithm Multi class Type:Dos')
elif(l[2]==1):
   print('CNN Algorithm Multi class Type:Probe')
elif(l[4]==1):
   print('CNN Algorithm Multi class Type:R2L')
elif(l[3]==1):
   print('CNN Algorithm Multi class Type:U2R')
elif(l[0]==1):
   print('CNN Algorithm Multi class Type:NORMAL')
else:
   print("CNN Algorithm Multi class Type:can't be predicted")
val_lstm=lstm_bin.predict(l1,verbose=0)
tp=[]
for i in val_lstm:
  for j in i:
      tp.append(round(j))
if(tp[0]==1):
    print('LSTM Algorithm binary class: Attack')
else:
    print('LSTM Algorithm binary class: Normal')
tp_lstm=lstm_multi.predict(l1,verbose=0)
l=[]
for i in tp_lstm:
    for j in i:
        l.append(round(j))
if(l[1]==1):
   print('LSTM Algorithm Multi class Type:Dos')
elif(l[2]==1):
   print('LSTM Algorithm Multi class Type:Probe')
elif(l[4]==1):
   print('LSTM Algorithm Multi class Type:R2L')
elif(l[3]==1):
   print('LSTM Algorithm Multi class Type:U2R')
elif(l[0]==1):
   print('LSTM Algorithm Multi class Type:NORMAL')
else:
   print("LSTM Algorithm Multi class Type:can't be predicted")

# import sys
# a=sys.argv[1]
# b=sys.argv[2]
# c=sys.argv[3]
# d=sys.argv[4]
# e=sys.argv[5]
# f=sys.argv[6]
# g=sys.argv[7]
# h=sys.argv[8]
# i=sys.argv[9]
# j=sys.argv[10]
# k=sys.argv[11]
# l=sys.argv[12]
# m=sys.argv[13]
# n=sys.argv[14]
# o=sys.argv[15]
# p=sys.argv[16]
# print(a+b+c+d+e+f+g+h+i+j+k+l+m+n+o+p) 