// Copyright © 2019 Banzai Cloud
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package internalpki

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	"github.com/banzaicloud/kafka-operator/api/v1alpha1"
	"github.com/banzaicloud/kafka-operator/api/v1beta1"
	"github.com/banzaicloud/kafka-operator/pkg/resources/templates"
	certutil "github.com/banzaicloud/kafka-operator/pkg/util/cert"
	pkicommon "github.com/banzaicloud/kafka-operator/pkg/util/pki"
)

func createNewCA(ctx context.Context, client client.Client, cluster *v1beta1.KafkaCluster, scheme *runtime.Scheme) error {
	caSecret, err := newClusterCASecret(cluster, scheme)
	if err != nil {
		return err
	}
	return client.Create(ctx, caSecret)
}

func newClusterCASecret(cluster *v1beta1.KafkaCluster, scheme *runtime.Scheme) (*corev1.Secret, error) {
	ca := newCA(cluster.Name)
	caPrivKey, err := newKey()
	if err != nil {
		return nil, err
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, err
	}
	_, caPEM, caKeyPEM, err := encodeToPEM(ca, caBytes, caPrivKey)
	if err != nil {
		return nil, err
	}
	caSecret := &corev1.Secret{
		ObjectMeta: templates.ObjectMeta(fmt.Sprintf(pkicommon.BrokerCACertTemplate, cluster.Name), pkicommon.LabelsForKafkaPKI(cluster.Name), cluster),
		Data: map[string][]byte{
			v1alpha1.CoreCACertKey:  caPEM,
			corev1.TLSCertKey:       caPEM,
			corev1.TLSPrivateKeyKey: caKeyPEM,
		},
	}
	controllerutil.SetControllerReference(cluster, caSecret, scheme)
	return caSecret, nil
}

func getCA(ctx context.Context, client client.Client, cluster *v1beta1.KafkaCluster) (*x509.Certificate, *rsa.PrivateKey, error) {
	o := types.NamespacedName{
		Name:      fmt.Sprintf(pkicommon.BrokerCACertTemplate, cluster.Name),
		Namespace: cluster.Namespace,
	}
	caSecret := &corev1.Secret{}
	if err := client.Get(ctx, o, caSecret); err != nil {
		return nil, nil, err
	}
	cert, err := certutil.DecodeCertificate(caSecret.Data[corev1.TLSCertKey])
	if err != nil {
		return nil, nil, err
	}
	keyData, _ := pem.Decode(caSecret.Data[corev1.TLSPrivateKeyKey])
	privKey, err := x509.ParsePKCS8PrivateKey(keyData.Bytes)
	if err != nil {
		return nil, nil, err
	}
	return cert, privKey.(*rsa.PrivateKey), nil
}
