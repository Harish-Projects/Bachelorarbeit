**"Live Intrusion Detection System mit Shallow Machine Learning: Vergleich und Evaluation von Modellen in IoT- und IIoT-Umgebungen"**

Dataset: Edge-IIoT-Set (2022)

Models:
* Binary classsifier;
  * SVC - Model with SVM techniques.[Supervised]<br>
  * KNN - Model with cluster techniques.[Supervised]<br>
  * Local Outlier Factor - Model with density based techniques.[semi-supervised]<br>
  * Random Forest - Model with decison tree based techniques.[supervised]<br>
* Multiclass classifier;
  * SVC - SVM technique with non linear kernel trick and ONE-vs-ONE method.[Supervised]<br>
  * Linear SVC - Model with linear kernel and ONE-vs-REST method.[Supervised]<br>
  * KNN - Cluster technique.[Supervised]<br>
  * RF - Decision tree multiclass classifier.[supervised]<br> 

Evaluation: 
Accuracy, Precision, Recall, F1, Confusion Matrix and Novel Percentage. Novel percentage evaluates a Total True Positive when a model is trained with *leaving one target class out* approach. 

Directory Structure: