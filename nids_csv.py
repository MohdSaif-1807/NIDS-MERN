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
#Uploaded_files\fs_test.csv
path='Uploaded_files/'
path+=sys.argv[1];
f=open(path)
data_Validate=pd.read_csv(f)
columns = (['protocol_type','service','flag','logged_in','count','srv_serror_rate','srv_rerror_rate','same_srv_rate','diff_srv_rate','dst_host_count','dst_host_srv_count','dst_host_same_srv_rate','dst_host_diff_srv_rate','dst_host_same_src_port_rate','dst_host_serror_rate','dst_host_rerror_rate'])

data_Validate.columns=columns
protocol_type_le = LabelEncoder()
service_le = LabelEncoder()
flag_le = LabelEncoder()
data_Validate['protocol_type'] = protocol_type_le.fit_transform(data_Validate['protocol_type'])
data_Validate['service'] = service_le.fit_transform(data_Validate['service'])
data_Validate['flag'] = flag_le.fit_transform(data_Validate['flag'])
df_validate=data_Validate.copy(deep=True)
x_validate=df_validate.copy(deep=True)
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

x_predict_bin=knn_bin.predict(x_validate)
x_predict_multi=knn_multi.predict(x_validate)
l=[]
for i in x_predict_bin:
  if(i == 0):
    l.append('Normal')
  else:
    l.append('Attack')
l=np.array(l)
df_validate['binary class']=l
df_validate['multi class']=x_predict_multi
#print(l)
#df_validate
#print(df_validate['dst_host_srv_count'])
df_validate.to_csv(path,index=False)
print('completed!!')
'''df_validate.to_csv(f"f")
df=pd.read_csv('f',index_col=0)
df'''
