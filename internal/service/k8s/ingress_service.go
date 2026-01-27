package k8s

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// GetIngressList 获取 Ingress 列表
func (s *K8sService) GetIngressList(clusterID string, clusterName string, nodeID uint, envID uint, namespace string) ([]*Ingress, error) {
	cluster, err := s.GetClusterConfig(clusterID, clusterName)
	if err != nil && (clusterID == "" && clusterName == "") {
		return nil, fmt.Errorf("请提供 cluster_id 或 cluster_name")
	}
	if err != nil {
		return nil, err
	}

	ns := s.getNamespace(cluster, namespace)

	ingressURL := strings.TrimSuffix(cluster.APIServer, "/") + "/apis/networking.k8s.io/v1/namespaces/" + ns + "/ingresses"
	httpReq, client, err := s.createK8sHTTPClient(cluster, ingressURL)
	if err != nil {
		return nil, err
	}

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("请求失败: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("读取响应失败: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API请求失败: %s, 响应: %s", resp.Status, string(body))
	}

	var ingressListResponse struct {
		Items []struct {
			Metadata struct {
				Name              string `json:"name"`
				Namespace         string `json:"namespace"`
				CreationTimestamp string `json:"creationTimestamp"`
			} `json:"metadata"`
			Spec struct {
				Rules []struct {
					Host string `json:"host"`
				} `json:"rules"`
			} `json:"spec"`
			Status struct {
				LoadBalancer struct {
					Ingress []struct {
						IP       string `json:"ip"`
						Hostname string `json:"hostname"`
					} `json:"ingress"`
				} `json:"loadBalancer"`
			} `json:"status"`
		} `json:"items"`
	}

	if err := json.Unmarshal(body, &ingressListResponse); err != nil {
		return nil, fmt.Errorf("解析响应失败: %v", err)
	}

	ingresses := make([]*Ingress, 0, len(ingressListResponse.Items))
	for _, item := range ingressListResponse.Items {
		ingress := &Ingress{
			Name:      item.Metadata.Name,
			Namespace: item.Metadata.Namespace,
			Age:       formatAge(item.Metadata.CreationTimestamp),
		}

		// 提取地址
		var addresses []string
		for _, ingress := range item.Status.LoadBalancer.Ingress {
			if ingress.IP != "" {
				addresses = append(addresses, ingress.IP)
			} else if ingress.Hostname != "" {
				addresses = append(addresses, ingress.Hostname)
			}
		}
		if len(addresses) > 0 {
			ingress.Address = strings.Join(addresses, ",")
		} else {
			ingress.Address = "<pending>"
		}

		// 提取主机
		var hosts []string
		for _, rule := range item.Spec.Rules {
			if rule.Host != "" {
				hosts = append(hosts, rule.Host)
			}
		}
		ingress.Hosts = strings.Join(hosts, ",")

		ingresses = append(ingresses, ingress)
	}

	return ingresses, nil
}

