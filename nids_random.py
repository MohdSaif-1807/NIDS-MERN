import numpy as np
import sys
from sklearn.metrics import accuracy_score, confusion_matrix
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from sklearn.preprocessing import MinMaxScaler
import sklearn
from sklearn.neighbors import KNeighborsClassifier
import os
#from google.colab import drive
from sklearn.preprocessing import LabelEncoder
import tensorflow as tf
import pickle
data_Validate=pd.read_csv('fs_new validation project.csv')
columns = (['protocol_type','service','flag','logged_in','count','srv_serror_rate','srv_rerror_rate','same_srv_rate','diff_srv_rate','dst_host_count','dst_host_srv_count','dst_host_same_srv_rate','dst_host_diff_srv_rate','dst_host_same_src_port_rate','dst_host_serror_rate','dst_host_rerror_rate','attack'])
data_Validate.columns=columns
protocol_type_le = LabelEncoder()
service_le = LabelEncoder()
flag_le = LabelEncoder()
data_Validate['protocol_type'] = protocol_type_le.fit_transform(data_Validate['protocol_type'])
data_Validate['service'] = service_le.fit_transform(data_Validate['service'])
data_Validate['flag'] = flag_le.fit_transform(data_Validate['flag'])
df_validate=data_Validate.copy(deep=True)
x_validate=df_validate.drop(['attack'],axis=1)

label_encoder = LabelEncoder() 
scaler=MinMaxScaler()
x1=x_validate.copy(deep=True)
scaler=MinMaxScaler()
scaler.fit(x1)
scaled_data=scaler.transform(x1)
scaled_data=pd.DataFrame(scaled_data)
scaled_data.columns= x1.columns
x_validate=scaled_data

knn_bin = pickle.load(open('knn_binary_class.sav', 'rb'))
knn_multi = pickle.load(open('knn_multi_class.sav', 'rb'))
randfor_bin = pickle.load(open('random_forest_binary_class.sav', 'rb'))
randfor_multi = pickle.load(open('random_forest_multi_class.sav', 'rb'))
cnn_bin= tf.keras.models.load_model('cnn_binary_class.h5')
cnn_multi= tf.keras.models.load_model('cnn_multi_class.h5')
lstm_bin= tf.keras.models.load_model('lstm_binary_class.h5')
lstm_multi= tf.keras.models.load_model('lstm_multi_class.h5')

def advance():
    print("KNN ALGORITHM:")
    tp=x_validate.sample()
    val_knn=knn_bin.predict(tp)
    if(val_knn==1):
        print('KNN Binary Class Type : ATTACK')
        tp_knn=knn_multi.predict(tp)
        print('KNN Multi Class Type : ',tp_knn)
        if(tp_knn=='dos'):
            print('KNN Description : A Denial-of-Service (DoS) attack is an attack meant to shut down a machine or network, making it inaccessible to its intended users. DoS attacks accomplish this by flooding the target with traffic, or sending it information that triggers a crash. In both instances, the DoS attack deprives legitimate users (i.e. employees, members, or account holders) of the service or resource they expected.')
        elif(tp_knn=='probe'):
            print('KNN Description : Probing is another type of attack in which the intruder scans network devices to determine weakness in topology design or some opened ports and then use them in the future for illegal access to personal information.')
        elif(tp_knn=='r2l'):
            print('KNN Description : Remote to user (R2L) is a type of computer network attacks, in which an intruder sends set of packets to another computer or server over a network where he/she does not have permission to access as a local user.')
        elif(tp_knn=='u2r'):
            print('KNN Description : User to root attacks (U2R) is an another type of attack where the intruder tries to access the network resources as a normal user,  and after several attempts, the intruder becomes as a full access user.')
    elif(val_knn==0):
        print('KNN Binary Class Type : NORMAL')
        tp_knn=knn_multi.predict(tp)
        print('KNN Multi Class Type : ',tp_knn)
        if(tp_knn=='normal'):
            print('KNN Description : This Is Safe.')

    print("RANDOM FOREST ALGORITHM:")    
    val_randfor=randfor_bin.predict(tp)
    if(val_randfor==1):
        print('RANDOM FOREST Binary Class Type : ATTACK')
        tp_randfor=randfor_multi.predict(tp)
        print('RANDOM FOREST Multi Class Type : ',tp_randfor)
        if(tp_randfor=='Dos'):
            print('RANDOM FOREST Description : A Denial-of-Service (DoS) attack is an attack meant to shut down a machine or network, making it inaccessible to its intended users. DoS attacks accomplish this by flooding the target with traffic, or sending it information that triggers a crash. In both instances, the DoS attack deprives legitimate users (i.e. employees, members, or account holders) of the service or resource they expected.')
        elif(tp_randfor=='Probe'):
            print('RANDOM FOREST Description : Probing is another type of attack in which the intruder scans network devices to determine weakness in topology design or some opened ports and then use them in the future for illegal access to personal information.')
        elif(tp_randfor=='R2L'):
            print('RANDOM FOREST Description : Remote to user (R2L) is a type of computer network attacks, in which an intruder sends set of packets to another computer or server over a network where he/she does not have permission to access as a local user.')
        elif(tp_randfor=='U2R'):
            print('RANDOM FOREST Description : User to root attacks (U2R) is an another type of attack where the intruder tries to access the network resources as a normal user,  and after several attempts, the intruder becomes as a full access user.')
    elif(val_randfor==0):
        print('RANDOM FOREST Binary Class Type: NORMAL')
        tp_randfor=randfor_multi.predict(tp)
        print('RANDOM FOREST Multi Class Type : ',tp_randfor)
        if(tp_randfor=='normal'):
            print('RANDOM FOREST Description : This Is Safe.')

    print("CNN ALGORITHM:")
    val_cnn=cnn_bin.predict(tp,verbose=0)
    for i in val_cnn:
        for j in i:
            val_cnn=round(j)
    if(val_cnn==1):
        print('CNN Binary Class Type: ATTACK')
        tp_cnn=cnn_multi.predict(tp,verbose=0)
        l=[]
        for i in tp_cnn:
            for j in i:
                l.append(round(j))
        if(l[1]==1):
            print('CNN Multi Class Type : DoS')
            print('CNN Description : A Denial-of-Service (DoS) attack is an attack meant to shut down a machine or network, making it inaccessible to its intended users. DoS attacks accomplish this by flooding the target with traffic, or sending it information that triggers a crash. In both instances, the DoS attack deprives legitimate users (i.e. employees, members, or account holders) of the service or resource they expected.')
        elif(l[2]==1):
            print('CNN Multi Class Type : Probe')
            print('CNN Description : Probing is another type of attack in which the intruder scans network devices to determine weakness in topology design or some opened ports and then use them in the future for illegal access to personal information.')
        elif(l[4]==1):
            print('CNN Multi Class Type : R2L')
            print('CNN Description : Remote to user (R2L) is a type of computer network attacks, in which an intruder sends set of packets to another computer or server over a network where he/she does not have permission to access as a local user.')
        elif(l[3]==1):
            print('CNN Multi Class Type : U2R')
            print('CNN Description : User to root attacks (U2R) is an another type of attack where the intruder tries to access the network resources as a normal user,  and after several attempts, the intruder becomes as a full access user.')
        elif(l[0]==1):
            print('CNN Multi Class Type : NORMAL')
            print('CNN Description : This Is Safe')
        else:
            print("CNN Multi Class Type : Can't Be Predicted")
            print('CNN Unknown!')
    elif(val_cnn==0):
        print('CNN Binary Class Type : NORMAL')
        tp_cnn=cnn_multi.predict(tp,verbose=0)
        l=[]
        for i in tp_cnn:
            for j in i:
                l.append(round(j))
        if(l[1]==1):
            print('CNN Multi Class Type : DoS')
            print('CNN Description : A Denial-of-Service (DoS) attack is an attack meant to shut down a machine or network, making it inaccessible to its intended users. DoS attacks accomplish this by flooding the target with traffic, or sending it information that triggers a crash. In both instances, the DoS attack deprives legitimate users (i.e. employees, members, or account holders) of the service or resource they expected.')
        elif(l[2]==1):
            print('CNN Multi Class Type : Probe')
            print('CNN Description : Probing is another type of attack in which the intruder scans network devices to determine weakness in topology design or some opened ports and then use them in the future for illegal access to personal information.')
        elif(l[4]==1):
            print('CNN Multi Class Type : R2L')
            print('CNN Description : Remote to user (R2L) is a type of computer network attacks, in which an intruder sends set of packets to another computer or server over a network where he/she does not have permission to access as a local user.')
        elif(l[3]==1):
            print('CNN Multi Class Type : U2R')
            print('CNN Description : User to root attacks (U2R) is an another type of attack where the intruder tries to access the network resources as a normal user,  and after several attempts, the intruder becomes as a full access user.')
        elif(l[0]==1):
            print('CNN Multi Class Type : Normal')
            print('CNN Description : This Is Safe')
        else:
            print("CNN Multi Class Type : Can't Be Predicted")
            print('CNN Unknown!')

    print("LSTM ALGORITHM:")
    val_lstm=lstm_bin.predict(tp,verbose=0)
    for i in val_lstm:
        for j in i:
            val_lstm=round(j)
    if(val_lstm==1):
        print('LSTM Binary Class Type : ATTACK')
        tp_lstm=lstm_multi.predict(tp,verbose=0)
        l=[]
        for i in tp_lstm:
            for j in i:
                l.append(round(j))
        if(l[1]==1):
            print('LSTM Multi Class Type : DoS')
            print('LSTM Description : A Denial-of-Service (DoS) attack is an attack meant to shut down a machine or network, making it inaccessible to its intended users. DoS attacks accomplish this by flooding the target with traffic, or sending it information that triggers a crash. In both instances, the DoS attack deprives legitimate users (i.e. employees, members, or account holders) of the service or resource they expected.')
        elif(l[2]==1):
            print('LSTM Multi Class Type : Probe')
            print('LSTM Description : Probing is another type of attack in which the intruder scans network devices to determine weakness in topology design or some opened ports and then use them in the future for illegal access to personal information.')
        elif(l[4]==1):
            print('LSTM Multi Class Type : R2L')
            print('LSTM Description : Remote to user (R2L) is a type of computer network attacks, in which an intruder sends set of packets to another computer or server over a network where he/she does not have permission to access as a local user.')
        elif(l[3]==1):
            print('LSTM Multi Class Type:U2R')
            print('LSTM Description : User to root attacks (U2R) is an another type of attack where the intruder tries to access the network resources as a normal user,  and after several attempts, the intruder becomes as a full access user.')
        elif(l[0]==1):
            print('LSTM Multi class Type : Normal')
            print('LSTM Description : This Is Safe')
        else:
            print("LSTM Multi Class Type : Can't Be Predicted")
            print('LSTM Unknown!')
    elif(round(val_lstm)==0):
        print('LSTM-Binary Class Type : NORMAL')
        tp_lstm=lstm_multi.predict(tp,verbose=0)
        l=[]
        for i in tp_lstm:
            for j in i:
                l.append(round(j))
        if(l[1]==1):
            print('LSTM Multi Class Type : DoS')
            print('LSTM Description : A Denial-of-Service (DoS) attack is an attack meant to shut down a machine or network, making it inaccessible to its intended users. DoS attacks accomplish this by flooding the target with traffic, or sending it information that triggers a crash. In both instances, the DoS attack deprives legitimate users (i.e. employees, members, or account holders) of the service or resource they expected.')
        elif(l[2]==1):
            print('LSTM Multi Class Type : Probe')
            print('LSTM Description : Probing is another type of attack in which the intruder scans network devices to determine weakness in topology design or some opened ports and then use them in the future for illegal access to personal information.')
        elif(l[4]==1):
            print('LSTM Multi Class Type : R2L')
            print('LSTM Description : Remote to user (R2L) is a type of computer network attacks, in which an intruder sends set of packets to another computer or server over a network where he/she does not have permission to access as a local user.')
        elif(l[3]==1):
            print('LSTM Multi Class Type : U2R')
            print('LSTM Description : User to root attacks (U2R) is an another type of attack where the intruder tries to access the network resources as a normal user,  and after several attempts, the intruder becomes as a full access user.')
        elif(l[0]==1):
            print('LSTM Multi Class Type : Normal')
            print('LSTM Description : This Is Safe')
        else:
            print("LSTM Multi Class Type : Can't Be Predicted")
            print('LSTM Unknown!')

advance()
            
    
    
