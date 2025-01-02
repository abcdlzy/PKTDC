namespace PcapCompressor
{
    partial class Form1
    {
        /// <summary>
        ///  Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        ///  Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        ///  Required method for Designer support - do not modify
        ///  the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            btnRun = new Button();
            btnsave = new Button();
            btnRecovery = new Button();
            tbSourceFile = new TextBox();
            btnSaveSrc = new Button();
            tbOutputPath = new TextBox();
            btnTest = new Button();
            btnRecoveryTargetPkt = new Button();
            label1 = new Label();
            label2 = new Label();
            tbFindIP = new TextBox();
            lbfind = new Label();
            btnSourceFile = new Button();
            btnOutputFile = new Button();
            tbMsg = new TextBox();
            label3 = new Label();
            btnSetThreadCount = new Button();
            tbThreadCount = new TextBox();
            btnAutoTest = new Button();
            btnAutoRecoveryTest = new Button();
            btnAutoAll = new Button();
            btnPowershell = new Button();
            tbPowershell = new TextBox();
            SuspendLayout();
            // 
            // btnRun
            // 
            btnRun.Location = new Point(609, 404);
            btnRun.Name = "btnRun";
            btnRun.Size = new Size(75, 23);
            btnRun.TabIndex = 0;
            btnRun.Text = "run";
            btnRun.UseVisualStyleBackColor = true;
            btnRun.Click += btnRun_Click;
            // 
            // btnsave
            // 
            btnsave.Location = new Point(609, 26);
            btnsave.Name = "btnsave";
            btnsave.Size = new Size(75, 23);
            btnsave.TabIndex = 1;
            btnsave.Text = "save";
            btnsave.UseVisualStyleBackColor = true;
            btnsave.Click += btnsave_Click;
            // 
            // btnRecovery
            // 
            btnRecovery.Location = new Point(609, 89);
            btnRecovery.Name = "btnRecovery";
            btnRecovery.Size = new Size(75, 23);
            btnRecovery.TabIndex = 2;
            btnRecovery.Text = "recovery";
            btnRecovery.UseVisualStyleBackColor = true;
            btnRecovery.Click += btnRecovery_Click;
            // 
            // tbSourceFile
            // 
            tbSourceFile.Location = new Point(85, 24);
            tbSourceFile.Name = "tbSourceFile";
            tbSourceFile.Size = new Size(388, 23);
            tbSourceFile.TabIndex = 3;
            tbSourceFile.Text = "C:\\project\\PcapCompressor\\202304021400.pcap";
            // 
            // btnSaveSrc
            // 
            btnSaveSrc.Location = new Point(609, 146);
            btnSaveSrc.Name = "btnSaveSrc";
            btnSaveSrc.Size = new Size(174, 23);
            btnSaveSrc.TabIndex = 4;
            btnSaveSrc.Text = "save source headers";
            btnSaveSrc.UseVisualStyleBackColor = true;
            btnSaveSrc.Click += btnSaveSrc_Click;
            // 
            // tbOutputPath
            // 
            tbOutputPath.Location = new Point(85, 62);
            tbOutputPath.Name = "tbOutputPath";
            tbOutputPath.Size = new Size(388, 23);
            tbOutputPath.TabIndex = 5;
            tbOutputPath.Text = "C:\\project\\PcapCompressor\\output-exp.7z";
            // 
            // btnTest
            // 
            btnTest.Location = new Point(609, 375);
            btnTest.Name = "btnTest";
            btnTest.Size = new Size(75, 23);
            btnTest.TabIndex = 6;
            btnTest.Text = "test";
            btnTest.UseVisualStyleBackColor = true;
            btnTest.Click += btnTest_Click;
            // 
            // btnRecoveryTargetPkt
            // 
            btnRecoveryTargetPkt.Location = new Point(609, 196);
            btnRecoveryTargetPkt.Name = "btnRecoveryTargetPkt";
            btnRecoveryTargetPkt.Size = new Size(179, 23);
            btnRecoveryTargetPkt.TabIndex = 7;
            btnRecoveryTargetPkt.Text = "recover target pkt";
            btnRecoveryTargetPkt.UseVisualStyleBackColor = true;
            btnRecoveryTargetPkt.Click += btnRecoveryTargetPkt_Click;
            // 
            // label1
            // 
            label1.AutoSize = true;
            label1.Location = new Point(25, 26);
            label1.Name = "label1";
            label1.Size = new Size(47, 17);
            label1.TabIndex = 8;
            label1.Text = "source";
            // 
            // label2
            // 
            label2.AutoSize = true;
            label2.Location = new Point(25, 65);
            label2.Name = "label2";
            label2.Size = new Size(46, 17);
            label2.TabIndex = 9;
            label2.Text = "output";
            // 
            // tbFindIP
            // 
            tbFindIP.Location = new Point(88, 99);
            tbFindIP.Name = "tbFindIP";
            tbFindIP.Size = new Size(205, 23);
            tbFindIP.TabIndex = 10;
            tbFindIP.Text = "201.105.59.16";
            // 
            // lbfind
            // 
            lbfind.AutoSize = true;
            lbfind.Location = new Point(25, 103);
            lbfind.Name = "lbfind";
            lbfind.Size = new Size(30, 17);
            lbfind.TabIndex = 11;
            lbfind.Text = "find";
            // 
            // btnSourceFile
            // 
            btnSourceFile.Location = new Point(487, 25);
            btnSourceFile.Name = "btnSourceFile";
            btnSourceFile.Size = new Size(75, 23);
            btnSourceFile.TabIndex = 12;
            btnSourceFile.Text = "select file";
            btnSourceFile.UseVisualStyleBackColor = true;
            btnSourceFile.Click += btnSourceFile_Click;
            // 
            // btnOutputFile
            // 
            btnOutputFile.Location = new Point(487, 62);
            btnOutputFile.Name = "btnOutputFile";
            btnOutputFile.Size = new Size(75, 23);
            btnOutputFile.TabIndex = 13;
            btnOutputFile.Text = "select file";
            btnOutputFile.UseVisualStyleBackColor = true;
            btnOutputFile.Click += btnOutputFile_Click;
            // 
            // tbMsg
            // 
            tbMsg.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left;
            tbMsg.Location = new Point(29, 223);
            tbMsg.MaxLength = 10000000;
            tbMsg.Multiline = true;
            tbMsg.Name = "tbMsg";
            tbMsg.ScrollBars = ScrollBars.Both;
            tbMsg.Size = new Size(559, 215);
            tbMsg.TabIndex = 14;
            tbMsg.TextChanged += tbMsg_TextChanged;
            // 
            // label3
            // 
            label3.AutoSize = true;
            label3.Location = new Point(29, 140);
            label3.Name = "label3";
            label3.Size = new Size(87, 17);
            label3.TabIndex = 15;
            label3.Text = "Thread Count";
            label3.Click += label3_Click;
            // 
            // btnSetThreadCount
            // 
            btnSetThreadCount.Location = new Point(205, 137);
            btnSetThreadCount.Name = "btnSetThreadCount";
            btnSetThreadCount.Size = new Size(75, 23);
            btnSetThreadCount.TabIndex = 16;
            btnSetThreadCount.Text = "Set";
            btnSetThreadCount.UseVisualStyleBackColor = true;
            btnSetThreadCount.Click += btnSetThreadCount_Click;
            // 
            // tbThreadCount
            // 
            tbThreadCount.Location = new Point(123, 137);
            tbThreadCount.Name = "tbThreadCount";
            tbThreadCount.Size = new Size(76, 23);
            tbThreadCount.TabIndex = 17;
            // 
            // btnAutoTest
            // 
            btnAutoTest.Location = new Point(610, 281);
            btnAutoTest.Name = "btnAutoTest";
            btnAutoTest.Size = new Size(173, 23);
            btnAutoTest.TabIndex = 18;
            btnAutoTest.Text = "auto save test";
            btnAutoTest.UseVisualStyleBackColor = true;
            btnAutoTest.Click += btnAutoTest_Click;
            // 
            // btnAutoRecoveryTest
            // 
            btnAutoRecoveryTest.Location = new Point(610, 241);
            btnAutoRecoveryTest.Name = "btnAutoRecoveryTest";
            btnAutoRecoveryTest.Size = new Size(173, 23);
            btnAutoRecoveryTest.TabIndex = 19;
            btnAutoRecoveryTest.Text = "auto recovery test";
            btnAutoRecoveryTest.UseVisualStyleBackColor = true;
            btnAutoRecoveryTest.Click += btnAutoRecoveryTest_Click;
            // 
            // btnAutoAll
            // 
            btnAutoAll.Location = new Point(440, 173);
            btnAutoAll.Name = "btnAutoAll";
            btnAutoAll.Size = new Size(75, 23);
            btnAutoAll.TabIndex = 20;
            btnAutoAll.Text = "auto all";
            btnAutoAll.UseVisualStyleBackColor = true;
            btnAutoAll.Click += btnAutoAll_Click;
            // 
            // btnPowershell
            // 
            btnPowershell.Location = new Point(610, 333);
            btnPowershell.Name = "btnPowershell";
            btnPowershell.Size = new Size(173, 23);
            btnPowershell.TabIndex = 21;
            btnPowershell.Text = "build Powershell Script";
            btnPowershell.UseVisualStyleBackColor = true;
            btnPowershell.Click += btnPowershell_Click;
            // 
            // tbPowershell
            // 
            tbPowershell.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left;
            tbPowershell.Location = new Point(805, 12);
            tbPowershell.MaxLength = 10000000;
            tbPowershell.Multiline = true;
            tbPowershell.Name = "tbPowershell";
            tbPowershell.ScrollBars = ScrollBars.Both;
            tbPowershell.Size = new Size(430, 426);
            tbPowershell.TabIndex = 22;
            // 
            // Form1
            // 
            AutoScaleDimensions = new SizeF(7F, 17F);
            AutoScaleMode = AutoScaleMode.Font;
            ClientSize = new Size(1247, 450);
            Controls.Add(tbPowershell);
            Controls.Add(btnPowershell);
            Controls.Add(btnAutoAll);
            Controls.Add(btnAutoRecoveryTest);
            Controls.Add(btnAutoTest);
            Controls.Add(tbThreadCount);
            Controls.Add(btnSetThreadCount);
            Controls.Add(label3);
            Controls.Add(tbMsg);
            Controls.Add(btnOutputFile);
            Controls.Add(btnSourceFile);
            Controls.Add(lbfind);
            Controls.Add(tbFindIP);
            Controls.Add(label2);
            Controls.Add(label1);
            Controls.Add(btnRecoveryTargetPkt);
            Controls.Add(btnTest);
            Controls.Add(tbOutputPath);
            Controls.Add(btnSaveSrc);
            Controls.Add(tbSourceFile);
            Controls.Add(btnRecovery);
            Controls.Add(btnsave);
            Controls.Add(btnRun);
            Name = "Form1";
            Text = "paper1";
            Load += Form1_Load;
            ResumeLayout(false);
            PerformLayout();
        }

        #endregion

        private Button btnRun;
        private Button btnsave;
        private Button btnRecovery;
        private TextBox tbSourceFile;
        private Button btnSaveSrc;
        private TextBox tbOutputPath;
        private Button btnTest;
        private Button btnRecoveryTargetPkt;
        private Label label1;
        private Label label2;
        private TextBox tbFindIP;
        private Label lbfind;
        private Button btnSourceFile;
        private Button btnOutputFile;
        private TextBox tbMsg;
        private Label label3;
        private Button btnSetThreadCount;
        private TextBox tbThreadCount;
        private Button btnAutoTest;
        private Button btnAutoRecoveryTest;
        private Button btnAutoAll;
        private Button btnPowershell;
        private TextBox tbPowershell;
    }
}