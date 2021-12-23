
// meinrouterDlg.h : 头文件
//

#pragma once


// CmeinrouterDlg 对话框
class CmeinrouterDlg : public CDialogEx
{
// 构造
public:
	CmeinrouterDlg(CWnd* pParent = NULL);	// 标准构造函数


// 对话框数据
	enum { IDD = IDD_MYROUTER9_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnStartClickedButton();
	afx_msg void OnBnClickedButton();
//	afx_msg void OnAddClickedRouterButton();
//	afx_msg void OnBnClickedRouterButton();
	afx_msg void OnAddRouterButton();
//	afx_msg void OnDeleteRouterButton4();
	afx_msg void OnDeleteRouterButton();
		void CmeinrouterDlg::OnDestroy();
		void CmeinrouterDlg::OnTimer(UINT nIDEvent) ;
	CListBox	Logger;
	CListBox	m_RouteTable;
	CIPAddressCtrl	m_Destination;
	CIPAddressCtrl	m_NextHop;
	CIPAddressCtrl	m_Mask;

	afx_msg void OnLbnSelchangeList();
};
